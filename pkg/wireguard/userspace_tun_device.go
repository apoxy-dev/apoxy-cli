package wireguard

import (
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"k8s.io/utils/ptr"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const DefaultMTU = 1280 // IPv6 minimum MTU, required for some PPPoE links.

var _ tun.Device = (*tunDevice)(nil)

type tunDevice struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	nicID          tcpip.NICID
	pcapFile       *os.File
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
}

func newTunDevice(localAddresses []netip.Prefix, mtu *int, pcapPath string) (*tunDevice, error) {
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
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	tcpCCOpt := tcpip.CongestionControlOption("cubic")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpCCOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set TCP congestion control: %v", tcpipErr)
	}

	if mtu == nil {
		mtu = ptr.To(DefaultMTU)
	}

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, uint32(*mtu), "")
	var nicEP stack.LinkEndpoint = linkEP

	var pcapFile *os.File
	if pcapPath != "" {
		var err error
		pcapFile, err = os.Create(pcapPath)
		if err != nil {
			return nil, fmt.Errorf("could not create pcap file: %w", err)
		}

		nicEP, err = sniffer.NewWithWriter(linkEP, pcapFile, uint32(*mtu))
		if err != nil {
			return nil, fmt.Errorf("could not create packet sniffer: %w", err)
		}
	}

	if tcpipErr := ipstack.CreateNIC(nicID, nicEP); tcpipErr != nil {
		return nil, fmt.Errorf("could not create NIC: %v", tcpipErr)
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
	for _, prefix := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if prefix.Addr().Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if prefix.Addr().Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol: protoNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(prefix.Addr().AsSlice()),
				PrefixLen: prefix.Bits(),
			},
		}
		tcpipErr := ipstack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, fmt.Errorf("could not add protocol address: %v", tcpipErr)
		}
	}

	tunDev := &tunDevice{
		ep:             linkEP,
		stack:          ipstack,
		nicID:          nicID,
		pcapFile:       pcapFile,
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View),
		mtu:            int(linkEP.MTU()),
	}
	tunDev.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	return tunDev, nil
}

func (tun *tunDevice) Name() (string, error) { return "go", nil }

func (tun *tunDevice) File() *os.File { return nil }

func (tun *tunDevice) Events() <-chan tun.Event { return tun.events }

func (tun *tunDevice) MTU() (int, error) { return tun.mtu, nil }

func (tun *tunDevice) BatchSize() int { return 1 }

func (tun *tunDevice) Read(buf [][]byte, sizes []int, offset int) (int, error) {
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

func (tun *tunDevice) Write(buf [][]byte, offset int) (int, error) {
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

func (tun *tunDevice) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *tunDevice) Close() error {
	tun.stack.RemoveNIC(tun.nicID)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	if tun.pcapFile != nil {
		_ = tun.pcapFile.Close()
	}

	return nil
}
