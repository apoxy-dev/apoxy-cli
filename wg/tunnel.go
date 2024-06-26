// Package wg implements a WireGuard tunnel device and TCP/UDP
// forwarding.
package wg

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
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
	defaultMTU = 1280
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

func tcpHandler(
	ctx context.Context,
	ns *stack.Stack,
	nicID tcpip.NICID,
	ip6to4 netip.Prefix,
) func(req *tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		epID := req.ID()
		slog.Debug(fmt.Sprintf("TCP connection %v:%d -> %v:%d",
			addrFromNetstackIP(epID.LocalAddress),
			epID.LocalPort,
			addrFromNetstackIP(epID.RemoteAddress),
			epID.RemotePort))

		// TODO(dsky): Only do this if the route is not already in the routing table.
		// TODO(dsky): Also we should only handle packets addressed to the pre-configured (IPv6)
		// address (the .InternalAddress()).
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
		ep, tcpipErr := req.CreateEndpoint(&wq)
		if tcpipErr != nil {
			slog.Error("Failed to create overlay TCP endpoint",
				"error", tcpipErr,
				"srcIP", epID.LocalAddress,
				"srcPort", epID.LocalPort,
				"dstIP", epID.RemoteAddress,
				"dstPort", epID.RemotePort,
			)
			req.Complete(true) // send RST
			return
		}
		req.Complete(false)

		// Timeout forgotten connections.
		ep.SocketOptions().SetKeepAlive(true)
		ep.SocketOptions().SetDelayOption(false)

		c := gonet.NewTCPConn(&wq, ep)
		defer c.Close()

		slog.Debug(fmt.Sprintf("Forwarding TCP connection %v:%d -> 127.0.0.1:%d",
			addrFromNetstackIP(epID.RemoteAddress),
			epID.RemotePort,
			epID.LocalPort))

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
				slog.Debug("Event received, closing connection")
			}
			cancel()
		}()

		dstIPv4 := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		if localIP.Is6() && ip6to4.Contains(localIP) {
			// If the local IP is in the 6to4 range, extract last 32 bits and use as IPv4 address.
			dstIPv4 = netip.AddrFrom4([4]byte{localIP.As16()[12], localIP.As16()[13], localIP.As16()[14], localIP.As16()[15]})
		}

		slog.Debug("Dialing backend", "address", fmt.Sprintf("%v:%d", dstIPv4, epID.LocalPort))
		var d net.Dialer
		fwdC, dErr := d.DialContext(fwdCtx, "tcp", fmt.Sprintf("%v:%d", dstIPv4, epID.LocalPort))
		if dErr != nil {
			slog.Error("Failed to dial local server", "error", dErr)
			return
		}
		defer fwdC.Close()

		connClosed := make(chan error, 2)
		go func() {
			_, err := io.Copy(c, fwdC)
			connClosed <- err
		}()
		go func() {
			_, err := io.Copy(fwdC, c)
			connClosed <- err
		}()
		err := <-connClosed
		if err != nil {
			slog.Debug("Connection closed with error", "error", err)
		}

		slog.Debug(fmt.Sprintf("Closing TCP connection %v:%d -> 127.0.0.1:%d",
			addrFromNetstackIP(epID.RemoteAddress),
			epID.RemotePort,
			epID.LocalPort))
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
	ipstack      *stack.Stack
	tundev       *netTun
	wgdev        *device.Device
	wgKey        wgtypes.Key
	publicAddr   netip.AddrPort
	internalAddr netip.Prefix
}

func pickUnusedUDP4Port() (int, error) {
	for i := 0; i < 10; i++ {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		if err != nil {
			return 0, err
		}
		l, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return l.LocalAddr().(*net.UDPAddr).Port, nil
	}
	return 0, errors.New("could not find unused UDP port")
}

// CreateTunnel creates a new WireGuard device (userspace).
func CreateTunnel(
	ctx context.Context,
	projectID uuid.UUID,
	endpoint string,
	verbose bool,
) (*Tunnel, error) {
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

	ip6to4 := NewApoxy4To6Prefix(projectID, endpoint)
	tcpForwarder := tcp.NewForwarder(
		ipstack,
		0,     /* rcvWnd (0 - default) */
		65535, /* maxInFlight */
		tcpHandler(ctx, ipstack, nicID, ip6to4),
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

	listenPort, err := pickUnusedUDP4Port()
	if err != nil {
		return nil, fmt.Errorf("could not pick unused UDP port: %v", err)
	}

	extAddr, extPorts, err := TrySTUN(listenPort,
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
	slog.Debug(fmt.Sprintf("External address: %v:%d", extAddr, extPorts[0]))
	publicAddr, err := netip.ParseAddrPort(fmt.Sprintf("%v:%d", extAddr, extPorts[0]))
	if err != nil {
		return nil, fmt.Errorf("could not parse external address: %v", err)
	}

	pkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %v", err)
	}
	pkeyHex := hex.EncodeToString(pkey[:])

	devLogger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			if verbose {
				slog.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...interface{}) {
			slog.Error(fmt.Sprintf(format, args...))
		},
	}

	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), devLogger)
	cmd := &strings.Builder{}
	cmd.WriteString(fmt.Sprintf("private_key=%s\n", pkeyHex))
	cmd.WriteString(fmt.Sprintf("listen_port=%d\n", listenPort))
	if err := wgDev.IpcSet(cmd.String()); err != nil {
		return nil, fmt.Errorf("could not set WireGuard device configuration: %v", err)
	}
	if err := wgDev.Up(); err != nil {
		return nil, fmt.Errorf("could not bring up WireGuard device: %v", err)
	}

	return &Tunnel{
		ipstack:      ipstack,
		tundev:       tunDev,
		wgdev:        wgDev,
		wgKey:        pkey,
		publicAddr:   publicAddr,
		internalAddr: ip6to4,
	}, nil
}

func allowedIPsToString(allowedIPs []net.IPNet) string {
	var sb strings.Builder
	for i, ipNet := range allowedIPs {
		sb.WriteString(ipNet.String())
		if i < len(allowedIPs)-1 {
			sb.WriteRune(',')
		}
	}
	return sb.String()
}

func (t *Tunnel) AddPeer(
	pubKeyHex string,
	endpoint netip.AddrPort,
	allowedIPs []net.IPNet,
	persistentKeepaliveInterval time.Duration,
) error {
	if pubKeyHex == "" {
		return errors.New("public key is required")
	}
	if len(allowedIPs) == 0 {
		return errors.New("allowed IPs are required")
	}

	peer := fmt.Sprintf(`public_key=%s
allowed_ip=%s`,
		pubKeyHex,
		allowedIPsToString(allowedIPs),
	)
	if endpoint.IsValid() {
		peer += fmt.Sprintf(`
endpoint=%s`, endpoint)
	}
	if persistentKeepaliveInterval > 0 {
		peer += fmt.Sprintf(`
persistent_keepalive_interval=%d`, int(persistentKeepaliveInterval.Seconds()))
	}

	return t.wgdev.IpcSet(peer)
}

func (t *Tunnel) PubKey() wgtypes.Key {
	return t.wgKey.PublicKey()
}

func (t *Tunnel) ExternalAddress() netip.AddrPort {
	return t.publicAddr
}

func (t *Tunnel) InternalAddress() netip.Prefix {
	return t.internalAddr
}

func (t *Tunnel) RemovePeer(pubKeyHex string) error {
	buf := &strings.Builder{}
	buf.WriteString(fmt.Sprintf("public_key=%s\n", pubKeyHex))
	buf.WriteString("remove=true")
	return t.wgdev.IpcSet(buf.String())
}

func (t *Tunnel) Close() {
	t.wgdev.Close()
	t.ipstack.Close()
}
