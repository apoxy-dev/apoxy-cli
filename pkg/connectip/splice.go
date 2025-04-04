package connectip

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	connectip "github.com/quic-go/connect-ip-go"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
)

func spliceConnToTunDevice(conn *connectip.Conn, tun tun.Device) error {
	var g errgroup.Group

	g.Go(func() error {
		var pkt [netstack.IPv6MinMTU]byte
		sizes := make([]int, 1)

		for {
			_, err := tun.Read([][]byte{pkt[:]}, sizes, 0)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					// TUN device is closed, exit the loop.
					// TODO: is this the correct error
					return nil
				}

				return fmt.Errorf("failed to read from TUN: %w", err)
			}

			slog.Debug("Read packet from TUN", slog.Int("len", sizes[0]))

			icmp, err := conn.WritePacket(pkt[:sizes[0]])
			if err != nil {
				slog.Error("Failed to write to connection", slog.Any("error", err))
				continue
			}
			if len(icmp) > 0 {
				slog.Debug("Sending ICMP packet")

				if _, err := t.tun.Write([][]byte{icmp}, 0); err != nil {
					slog.Error("Failed to write ICMP packet", slog.Any("error", err))
				}
			}
		}
	})

	g.Go(func() error {
		var pkt [netstack.IPv6MinMTU]byte

		for {
			n, err := conn.ReadPacket(pkt[:])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("failed to read from connection: %w", err)
			}

			slog.Debug("Read from connection", slog.Int("bytes", n))

			if _, err := tun.Write([][]byte{pkt[:n]}, 0); err != nil {
				slog.Error("Failed to write to TUN", slog.Any("error", err))
				continue
			}
		}
	})

	return g.Wait()
}
