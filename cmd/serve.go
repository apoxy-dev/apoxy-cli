package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	_ "golang.zx2c4.com/wireguard/tun/netstack"
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

func copyFromNetstackToTUN(ctx context.Context, ep *channel.Endpoint, tunDev tun.Device) {
	for {
		pkt := ep.ReadContext(ctx)
		if pkt.IsNil() {
			continue
		}
		buf := pkt.ToBuffer()
		bytes := (&buf).Flatten()
		const writeOffset = device.MessageTransportHeaderSize
		moreBytes := make([]byte, writeOffset, len(bytes)+writeOffset)
		moreBytes = append(moreBytes[:writeOffset], bytes...)

		if _, err := tunDev.Write([][]byte{moreBytes}, writeOffset); err != nil {
			fmt.Printf("Failed to write to TUN device: %v\n", err)
			return
		}
	}
}

func copyFromTUNToNetstack(ctx context.Context, tunDev tun.Device, ep *channel.Endpoint) {
	buffers := make([][]byte, tunDev.BatchSize())
	for i := range buffers {
		buffers[i] = make([]byte, device.MaxMessageSize)
	}
	const readOffset = device.MessageTransportHeaderSize
	sizes := make([]int, len(buffers))
	for {
		for i := range buffers {
			buffers[i] = buffers[i][:cap(buffers[i])]
		}
		n, err := tunDev.Read(buffers, sizes, readOffset)
		if err != nil {
			fmt.Printf("Failed to read from TUN device: %v\n", err)
		}
		fmt.Printf("Read %d packets from TUN device\n", n)
		for i := range sizes[:n] {
			buffers[i] = buffers[i][readOffset : readOffset+sizes[i]]
			// ready to send data to channel
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buffers[i])),
			})
			ep.InjectInbound(header.IPv4ProtocolNumber, packetBuf)
			packetBuf.DecRef()
		}
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

func createTunnel(ctx context.Context) error {
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
		return fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	nicID := tcpip.NICID(ipstack.UniqueID())
	linkEP := channel.New(512, uint32(defaultMTU), "")
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		return fmt.Errorf("could not create NIC: %v", err)
	}
	ipstack.SetPromiscuousMode(nicID, true)

	ipv4Subnet, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(make([]byte, 4)),
		tcpip.MaskFromBytes(make([]byte, 4)),
	)
	if err != nil {
		return fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	ipv6Subnet, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(make([]byte, 16)),
		tcpip.MaskFromBytes(make([]byte, 16)),
	)
	if err != nil {
		return fmt.Errorf("could not create IPv6 subnet: %v", err)
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
		0,    /* rcvWnd (0 - default) */
		4096, /* maxInFlight */
		tcpHandler(ctx, ipstack, nicID),
	)
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	tunDev := &netTun{
		ep:             linkEP,
		stack:          ipstack,
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            defaultMTU,
	}
	tunDev.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	wgDev.IpcSet(`private_key=003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641
listen_port=58120
public_key=f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c
allowed_ip=192.168.4.28/32
persistent_keepalive_interval=25
`)
	wgDev.Up()

	<-ctx.Done()

	return nil
}

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Create a secure tunnel to the remote Apoxy Edge fabric",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		if err := createTunnel(cmd.Context()); err != nil {
			return fmt.Errorf("unable to create tunnel: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
}
