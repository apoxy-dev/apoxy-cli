package connip

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/dpeckett/triemap"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

// Connection is a simple interface implemented by connect-ip-go and custom
// connection types.
type Connection interface {
	io.Closer
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
}

var _ Connection = (*MuxedConnection)(nil)

// MuxedConnection is a connection that multiplexes multiple downstream
// connections over a single virtual connection.
type MuxedConnection struct {
	// Maps tunnel destination address to CONNECT-IP connection.
	conns            *triemap.TrieMap[Connection]
	incomingPackets  chan *[]byte
	packetBufferPool sync.Pool
}

func NewMuxedConnection() *MuxedConnection {
	return &MuxedConnection{
		conns:           triemap.New[Connection](),
		incomingPackets: make(chan *[]byte, 100),
		packetBufferPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, netstack.IPv6MinMTU)
				return &b
			},
		},
	}
}

func (m *MuxedConnection) AddConnection(prefix netip.Prefix, conn Connection) {
	if prefix.IsValid() && prefix.Addr().Is6() {
		m.conns.Insert(prefix, conn)
		go m.readPackets(conn)
	} else {
		slog.Warn("Invalid prefix for connection", slog.String("prefix", prefix.String()))
	}
}

func (m *MuxedConnection) RemoveConnection(prefix netip.Prefix) error {
	if prefix.IsValid() && prefix.Addr().Is6() {
		conn, ok := m.conns.Get(prefix.Addr())
		if !ok {
			return fmt.Errorf("no connection found for prefix: %s", prefix.String())
		}

		// Close the connection and remove it from the map.
		if err := conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}

		// Remove the connection from the map.
		m.conns.Remove(prefix)
	} else {
		return fmt.Errorf("invalid prefix for connection: %s", prefix.String())
	}
	return nil
}

func (m *MuxedConnection) Close() error {
	// Close all connections in the map.
	m.conns.ForEach(func(prefix netip.Prefix, conn Connection) bool {
		if err := conn.Close(); err != nil {
			slog.Warn("Failed to close connection",
				slog.String("prefix", prefix.String()), slog.Any("error", err))
		}
		return true
	})

	// Clear the map.
	m.conns.Clear()

	// Close the incoming packets channel.
	close(m.incomingPackets)

	return nil
}

func (m *MuxedConnection) ReadPacket(pkt []byte) (int, error) {
	p, ok := <-m.incomingPackets
	if !ok {
		return 0, net.ErrClosed
	}

	n := copy(pkt, *p)

	// Slice len must be reset to capacity or else next time it's used,
	// it may be too short.
	*p = (*p)[:cap(*p)]
	m.packetBufferPool.Put(p)

	return n, nil
}

func (m *MuxedConnection) WritePacket(pkt []byte) ([]byte, error) {
	slog.Debug("Write packet to connection", slog.Int("bytes", len(pkt)))

	var dstIP netip.Addr
	switch pkt[0] >> 4 {
	case 6:
		// IPv6 packet (RFC 8200)
		if len(pkt) >= 40 {
			var addr [16]byte
			copy(addr[:], pkt[24:40])
			dstIP = netip.AddrFrom16(addr)
		} else {
			return nil, fmt.Errorf("IPv6 packet too short: %d", len(pkt))
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %d", pkt[0]>>4)
	}

	if !dstIP.IsValid() || !dstIP.Is6() || !dstIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("invalid destination IP: %s", dstIP.String())
	}

	slog.Debug("Packet destination", slog.String("ip", dstIP.String()))

	conn, ok := m.conns.Get(dstIP)
	if !ok {
		return nil, fmt.Errorf("no matching tunnel found for destination IP: %s", dstIP.String())
	}

	return conn.WritePacket(pkt)
}

func (m *MuxedConnection) readPackets(conn Connection) {
	for {
		pkt := m.packetBufferPool.Get().(*[]byte)

		n, err := conn.ReadPacket(*pkt)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("Failed to read from connection", slog.Any("error", err))
			}

			break
		}

		slog.Debug("Read packet from connection", slog.Int("bytes", n))

		*pkt = (*pkt)[:n]
		m.incomingPackets <- pkt
	}
}
