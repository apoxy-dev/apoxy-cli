// Package wg implements a WireGuard tunnel device and TCP/UDP
// forwarding.
package wg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunName    = "utun7"
	defaultMTU = 1420
)

func addrFromNetstackIP(ip tcpip.Address) netip.Addr {
	switch ip.Len() {
	case 4:
		ip := ip.As4()
		return netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	case 16:
		ip := ip.As16()
		return netip.AddrFrom16(ip).Unmap()
	}
	return netip.Addr{}
}

func tcpHandler(ctx context.Context, ns *stack.Stack, nicID tcpip.NICID) func(req *tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		epID := req.ID()
		fmt.Printf("TCP connection %v:%d -> %v:%d\n", addrFromNetstackIP(epID.LocalAddress), epID.LocalPort, addrFromNetstackIP(epID.RemoteAddress), epID.RemotePort)

		// TODO(dsky): Only do this if the route is not already in the routing table.
		localIP := addrFromNetstackIP(epID.LocalAddress)
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddrFromSlice(localIP.AsSlice()).WithPrefix(),
			Protocol:          ipv4.ProtocolNumber,
		}
		if localIP.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		ns.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint,
			ConfigType: stack.AddressConfigStatic,
		})

		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			fmt.Printf("Failed to create endpoint: %v\n", err)
			req.Complete(true /* send RST */)
			return
		}
		req.Complete(false)

		// Timeout forgotten connections.
		ep.SocketOptions().SetKeepAlive(true)

		c := gonet.NewTCPConn(&wq, ep)
		defer c.Close()

		fmt.Printf("Forwarding TCP connection %v:%d -> 127.0.0.1:%d\n",
			addrFromNetstackIP(epID.RemoteAddress),
			epID.RemotePort,
			epID.LocalPort)

		fwdCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Forward the connection to the local server.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-done:
			case <-notifyCh:
				fmt.Printf("Event received, closing connection\n")
			}
			cancel()
		}()

		var d net.Dialer
		fwdC, dErr := d.DialContext(fwdCtx, "tcp", fmt.Sprintf(":%d", epID.LocalPort))
		if dErr != nil {
			fmt.Printf("Failed to dial local server: %v\n", err)
			return
		}
		defer fwdC.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := io.Copy(c, fwdC); err != nil {
				fmt.Printf("Failed to copy from netstack to local server: %v\n", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := io.Copy(fwdC, c); err != nil {
				fmt.Printf("Failed to copy from local server to netstack: %v\n", err)
			}
		}()
		wg.Wait()

		fmt.Printf("Closing TCP connection %v:%d -> 127.0.0.1:%d\n", addrFromNetstackIP(epID.RemoteAddress), epID.RemotePort, epID.LocalPort)
	}
}

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
	hasV4, hasV6   bool
}

func (tun *netTun) Name() (string, error) { return "go", nil }
func (tun *netTun) File() *os.File        { return nil }

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
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

func (tun *netTun) Write(buf [][]byte, offset int) (int, error) {
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

func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

func (tun *netTun) MTU() (int, error) { return tun.mtu, nil }
func (tun *netTun) BatchSize() int    { return 1 }

var _ tun.Device = (*netTun)(nil)

type Tunnel struct {
	ipstack    *stack.Stack
	tundev     *netTun
	wgdev      *device.Device
	publicAddr netip.AddrPort
}

// CreateTunnel creates a new WireGuard device (userspace).
func CreateTunnel(ctx context.Context) (*Tunnel, error) {
	ipstack := stack.New(stack.Options{
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
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // Enable SACK cuz we're not savages.
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}

	nicID := tcpip.NICID(ipstack.UniqueID())
	linkEP := channel.New(4096, uint32(defaultMTU), "")
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("could not create NIC: %v", err)
	}
	ipstack.SetPromiscuousMode(nicID, true)

	ipv4Subnet, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(make([]byte, 4)),
		tcpip.MaskFromBytes(make([]byte, 4)),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	ipv6Subnet, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(make([]byte, 16)),
		tcpip.MaskFromBytes(make([]byte, 16)),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create IPv6 subnet: %v", err)
	}
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})

	tcpForwarder := tcp.NewForwarder(
		ipstack,
		0,     /* rcvWnd (0 - default) */
		65535, /* maxInFlight */
		tcpHandler(ctx, ipstack, nicID),
	)
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	tunDev := &netTun{
		ep:             linkEP,
		stack:          ipstack,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View, 1000),
		mtu:            defaultMTU,
	}
	tunDev.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	extAddr, extPorts, err := trySTUN(58120,
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302")
	if err != nil {
		return nil, fmt.Errorf("could not get external port: %v", err)
	}
	// Check if the port mapping was stable.
	for _, port := range extPorts {
		if port != extPorts[0] {
			return nil, fmt.Errorf("external port mapping was not stable: %v", extPorts)
		}
	}
	fmt.Printf("External address: %v:%d\n", extAddr, extPorts[0])
	publicAddr, err := netip.ParseAddrPort(fmt.Sprintf("%v:%d", extAddr, extPorts[0]))
	if err != nil {
		return nil, fmt.Errorf("could not parse external address: %v", err)
	}

	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	wgDev.IpcSet(`private_key=003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641
listen_port=58120
public_key=f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c
allowed_ip=192.168.4.28/32
persistent_keepalive_interval=25
`)
	wgDev.Up()

	return &Tunnel{
		ipstack:    ipstack,
		tundev:     tunDev,
		wgdev:      wgDev,
		publicAddr: publicAddr,
	}, nil
}

func allowedIPsToString(allowedIPs []net.IPNet) string {
	var sb strings.Builder
	for _, ipNet := range allowedIPs {
		sb.WriteString(ipNet.String())
		sb.WriteRune(',')
	}
	return sb.String()
}

func (t *Tunnel) AddPeer(peer *wgtypes.Peer) error {
	return t.wgdev.IpcSet(fmt.Sprintf(`public_key=%s
		endpoint=%s
		allowed_ip=%s
		persistent_keepalive_interval=%d
		`,
		peer.PublicKey.String(),
		peer.Endpoint.String(),
		allowedIPsToString(peer.AllowedIPs),
		peer.PersistentKeepaliveInterval,
	))
}

func (t *Tunnel) RemovePeer(peer *wgtypes.Peer) error {
	return t.wgdev.IpcSet(fmt.Sprintf(`remove=%s`, peer.PublicKey.String()))
}

func (t *Tunnel) Close() {
	t.wgdev.Close()
	t.tundev.Close()
	t.ipstack.Close()
}
