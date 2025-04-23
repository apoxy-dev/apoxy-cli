package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

const (
	tunOffset = device.MessageTransportHeaderSize
)

func Splice(tun tun.Device, conn Connection) error {
	var g errgroup.Group

	g.Go(func() error {
		defer conn.Close()

		var pkt [netstack.IPv6MinMTU]byte
		sizes := make([]int, 1)

		for {
			_, err := tun.Read([][]byte{pkt[:]}, sizes, 0)
			if err != nil {
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

				if _, err := tun.Write([][]byte{icmp}, 0); err != nil {
					slog.Error("Failed to write ICMP packet", slog.Any("error", err))
				}
			}
		}
	})

	g.Go(func() error {
		var pkt [netstack.IPv6MinMTU + tunOffset]byte

		for {
			n, err := conn.ReadPacket(pkt[tunOffset:])
			if err != nil {
				return fmt.Errorf("failed to read from connection: %w", err)
			}

			slog.Debug("Read from connection", slog.Int("bytes", n))

			if _, err := tun.Write([][]byte{pkt[:n+tunOffset]}, tunOffset); err != nil {
				slog.Error("Failed to write to TUN", slog.Any("error", err))
				continue
			}
		}
	})

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to splice: %w", err)
	}

	return nil
}
