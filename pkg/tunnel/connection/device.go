package connection

import (
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/fasttun"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

var _ fasttun.Device = (*Device)(nil)

type Device struct {
	conn *connectip.Conn
}

func NewDevice(conn *connectip.Conn) *Device {
	return &Device{
		conn: conn,
	}
}

func (d *Device) Close() error {
	return d.conn.Close()
}

func (d *Device) MTU() (int, error) {
	return netstack.IPv6MinMTU, nil
}

func (d *Device) Name() string {
	return "connect-ip"
}

func (d *Device) NewPacketQueue() (fasttun.PacketQueue, error) {
	return &PacketQueue{
		conn: d.conn,
	}, nil
}

type PacketQueue struct {
	conn *connectip.Conn
}

func (q *PacketQueue) Close() error {
	return nil
}

func (q *PacketQueue) BatchSize() int {
	return 1
}

func (q *PacketQueue) Read(pkts [][]byte, sizes []int) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}

	n, err := q.conn.ReadPacket(pkts[0])
	if err != nil {
		return 0, err
	}

	sizes[0] = n
	return 1, nil
}

func (q *PacketQueue) Write(pkts [][]byte) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}

	icmp, err := q.conn.WritePacket(pkts[0])
	if err != nil {
		return 0, err
	}
	if icmp != nil {
		return 0, &quic.DatagramTooLargeError{}
	}

	return 1, nil
}
