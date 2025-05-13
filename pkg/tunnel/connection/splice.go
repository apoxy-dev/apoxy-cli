package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

const (
	tunOffset = device.MessageTransportHeaderSize
)

func Splice(tunDev tun.Device, conn Connection) error {
	var g errgroup.Group

	batchSize := tunDev.BatchSize()

	g.Go(func() error {
		defer conn.Close()

		sizes := make([]int, batchSize)
		pkts := make([][]byte, batchSize)
		for i := range pkts {
			pkts[i] = make([]byte, netstack.IPv6MinMTU)
		}

		for {
			n, err := tunDev.Read(pkts, sizes, 0)
			if err != nil {
				if errors.Is(err, tun.ErrTooManySegments) {
					slog.Warn("Dropped packets from multi-segment TUN read", slog.Any("error", err))
					continue
				}
				if strings.Contains(err.Error(), "closed") {
					slog.Debug("TUN device closed")
					return nil
				}
				return fmt.Errorf("failed to read from TUN: %w", err)
			}

			for i := 0; i < n; i++ {
				slog.Debug("Read packet from TUN", slog.Int("len", sizes[i]))

				icmp, err := conn.WritePacket(pkts[i][:sizes[i]])
				if err != nil {
					slog.Error("Failed to write to connection", slog.Any("error", err))
					continue
				}
				if len(icmp) > 0 {
					slog.Debug("Sending ICMP packet")
					if _, err := tunDev.Write([][]byte{icmp}, 0); err != nil {
						slog.Error("Failed to write ICMP packet", slog.Any("error", err))
					}
				}
			}
		}
	})

	g.Go(func() error {
		pkts := make([][]byte, batchSize)
		for i := range pkts {
			pkts[i] = make([]byte, netstack.IPv6MinMTU+tunOffset)
		}

		// TODO: batched write to TUN device, unfortunately ReadPacket() is blocking
		// and not batched which makes this tricky.

		for {
			n, err := conn.ReadPacket(pkts[0][tunOffset:])
			if err != nil {
				return fmt.Errorf("failed to read from connection: %w", err)
			}

			slog.Debug("Read from connection", slog.Int("bytes", n))

			if _, err := tunDev.Write([][]byte{pkts[0][:n+tunOffset]}, tunOffset); err != nil {
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
