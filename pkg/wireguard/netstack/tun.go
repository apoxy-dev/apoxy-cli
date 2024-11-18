package netstack

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"k8s.io/utils/ptr"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const DefaultMTU = 1280 // IPv6 minimum MTU, required for some PPPoE links.

type NetTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	nicID          tcpip.NICID
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
}

func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu *int) (tun.Device, *NetTun, error) {
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	}

	ipstack := stack.New(opts)

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // Enable SACK cuz we're not savages.
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}

	if mtu == nil {
		mtu = ptr.To(DefaultMTU)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(*mtu), "")
	if tcpipErr := ipstack.CreateNIC(nicID, linkEP); tcpipErr != nil {
		return nil, nil, fmt.Errorf("could not create NIC: %v", tcpipErr)
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// Add the local addresses to the NIC.
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := ipstack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, fmt.Errorf("could not add protocol address: %v", tcpipErr)
		}
	}

	tunDev := &NetTun{
		ep:             linkEP,
		stack:          ipstack,
		nicID:          nicID,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View),
		dnsServers:     dnsServers,
		mtu:            int(linkEP.MTU()),
	}
	tunDev.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	return tunDev, tunDev, nil
}

func (tun *NetTun) Name() (string, error) { return "go", nil }

func (tun *NetTun) File() *os.File { return nil }

func (tun *NetTun) Events() <-chan tun.Event { return tun.events }

func (tun *NetTun) MTU() (int, error) { return tun.mtu, nil }

func (tun *NetTun) BatchSize() int { return 1 }

func (tun *NetTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (tun *NetTun) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (tun *NetTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *NetTun) Close() error {
	tun.stack.RemoveNIC(tun.nicID)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

// LocalAddresses returns the list of local addresses assigned to the NetTun device.
func (tun *NetTun) LocalAddresses() []netip.Prefix {
	nic := tun.stack.NICInfo()[tun.nicID]

	var addrs []netip.Prefix
	for _, assignedAddr := range nic.ProtocolAddresses {
		addrs = append(addrs, netip.PrefixFrom(
			addrFromNetstackIP(assignedAddr.AddressWithPrefix.Address),
			assignedAddr.AddressWithPrefix.PrefixLen,
		))
	}

	return addrs
}

// DialContext establishes a connection to the specified network and address, resolving the hostname if necessary.
func (tun *NetTun) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		addrs, err := tun.LookupContextHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve hostname %s: %w", host, err)
		}

		// TODO: Use a proper IP address selection algorithm.
		addr, err = netip.ParseAddr(addrs[0])
		if err != nil {
			return nil, fmt.Errorf("could not parse IP address %s: %w", addrs[0], err)
		}
	}

	// Resolve the port to an integer.
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve port %d: %w", port, err)
	}

	// Convert to a netstack address.
	fa, pn := tun.convertToFullAddr(netip.AddrPortFrom(addr, uint16(port)))

	// Parse the network type to determine if it's a TCP or UDP connection.
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, tun.stack, fa, pn)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(tun.stack, nil, &fa, pn)
	default:
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
}

// LookupContextHost resolves the hostname to an IP address.
func (tun *NetTun) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	// If no custom DNS servers are set, use the default resolver.
	if len(tun.dnsServers) == 0 {
		return net.DefaultResolver.LookupHost(ctx, host)
	}

	// Use a custom resolver with the specified DNS servers.
	var resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return tun.DialContext(ctx, "udp", netip.AddrPortFrom(randomAddress(tun.dnsServers), 53).String())
		},
	}

	return resolver.LookupHost(ctx, host)
}

// EnableForwarding enables packet forwarding on the network interface.
// Promiscuous mode should be enabled if the network interface is expected
// to forward packets with a destination address different from the address
// assigned to the NIC, e.g., when acting as a router.
func (tun *NetTun) EnableForwarding(tcpHandler func(*stack.Stack, *tcp.ForwarderRequest), promiscuous bool) error {
	if promiscuous {
		// Allow outgoing packets to have a source address different from the address
		// assigned to the NIC.
		if tcpipErr := tun.stack.SetSpoofing(tun.nicID, true); tcpipErr != nil {
			return fmt.Errorf("failed to enable spoofing: %v", tcpipErr)
		}

		// Allow incoming packets to have a destination address different from the
		// address assigned to the NIC.
		if tcpipErr := tun.stack.SetPromiscuousMode(tun.nicID, true); tcpipErr != nil {
			return fmt.Errorf("failed to enable promiscuous mode: %v", tcpipErr)
		}
	}

	// Create and register a TCP forwarder to handle incoming TCP packets.
	tcpForwarder := tcp.NewForwarder(
		tun.stack,
		0,     /* rcvWnd (0 - default) */
		65535, /* maxInFlight */
		func(req *tcp.ForwarderRequest) {
			tcpHandler(tun.stack, req)
		},
	)
	tun.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	return nil
}

func (tun *NetTun) convertToFullAddr(addrPort netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if addrPort.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  tun.nicID,
		Addr: tcpip.AddrFromSlice(addrPort.Addr().AsSlice()),
		Port: addrPort.Port(),
	}, protoNumber
}

func randomAddress(addrs []netip.Addr) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}
	index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(addrs))))
	return addrs[index.Int64()]
}
