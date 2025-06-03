package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

const (
	tunOffset = device.MessageTransportHeaderSize
)

func Splice(tunDev tun.Device, conn Connection) error {
	var g errgroup.Group

	stats := newSpliceStats()

	batchSize := tunDev.BatchSize()

	g.Go(func() error {
		defer func() {
			slog.Debug("Stopped reading from TUN")
		}()

		defer conn.Close()

		sizes := make([]int, batchSize)
		pkts := make([][]byte, batchSize)
		for i := range pkts {
			pkts[i] = make([]byte, netstack.IPv6MinMTU)
		}

		for {
			n, err := tunDev.Read(pkts, sizes, 0)
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					slog.Debug("TUN device closed")
					return net.ErrClosed
				}

				if errors.Is(err, tun.ErrTooManySegments) {
					slog.Warn("Dropped packets from multi-segment TUN read", slog.Any("error", err))
					continue
				}

				return fmt.Errorf("failed to read from TUN: %w", err)
			}

			stats.recordReadBatch(n)

			for i := 0; i < n; i++ {
				slog.Debug("Read packet from TUN", slog.Int("len", sizes[i]))

				icmp, err := conn.WritePacket(pkts[i][:sizes[i]])
				if err != nil {
					if strings.Contains(err.Error(), "closed") {
						slog.Debug("Connection closed")
						return net.ErrClosed
					}

					slog.Error("Failed to write to connection", slog.Any("error", err))
					return fmt.Errorf("failed to write to connection: %w", err)
				}
				if len(icmp) > 0 {
					slog.Debug("Sending ICMP packet")
					if _, err := tunDev.Write([][]byte{icmp}, 0); err != nil {
						if strings.Contains(err.Error(), "closed") {
							slog.Debug("TUN device closed")
							return net.ErrClosed
						}

						slog.Error("Failed to write ICMP packet", slog.Any("error", err))
						return fmt.Errorf("failed to write ICMP packet: %w", err)
					}
				}
			}
		}
	})

	g.Go(func() error {
		defer func() {
			slog.Debug("Stopped reading from connection")
		}()

		var pktPool = sync.Pool{
			New: func() any {
				return ptr.To(make([]byte, netstack.IPv6MinMTU+tunOffset))
			},
		}

		pktCh := make(chan *[]byte, batchSize)

		g.Go(func() error {
			defer close(pktCh)

			for {
				pkt := pktPool.Get().(*[]byte)
				n, err := conn.ReadPacket((*pkt)[tunOffset:])
				if err != nil {
					if strings.Contains(err.Error(), "closed") {
						slog.Debug("Connection closed")
						return net.ErrClosed
					}

					slog.Error("Failed to read from connection", slog.Any("error", err))
					return fmt.Errorf("failed to read from connection: %w", err)
				}

				slog.Debug("Read packet from connection", slog.Int("len", n))

				*pkt = (*pkt)[:n+tunOffset]
				pktCh <- pkt
			}
		})

		pkts := make([][]byte, batchSize)

		for {
			select {
			case pkt, ok := <-pktCh:
				if !ok {
					return nil
				}

				pkts[0] = *pkt
				batchCount := 1

				closed := false
			gatherBatch:
				for batchCount < batchSize && !closed {
					select {
					case pkt, ok := <-pktCh:
						if !ok {
							closed = true
							break
						}
						pkts[batchCount] = *pkt
						batchCount++
					default:
						break gatherBatch
					}
				}

				stats.recordWriteBatch(batchCount)

				if _, err := tunDev.Write(pkts[:batchCount], tunOffset); err != nil {
					if strings.Contains(err.Error(), "closed") {
						slog.Debug("TUN device closed")
						return net.ErrClosed
					}

					slog.Error("Failed to write to TUN", slog.Any("error", err))
					return fmt.Errorf("failed to write to TUN: %w", err)
				}

				for i := 0; i < batchCount; i++ {
					pkt := pkts[i][:cap(pkts[i])]
					pktPool.Put(&pkt)
				}
			}
		}
	})

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to splice: %w", err)
	}

	name, _ := tunDev.Name()

	slog.Debug("Splice completed",
		slog.String("name", name),
		slog.Int("batch_size", batchSize),
		slog.Any("read_summary", stats.readSummary()),
		slog.Any("write_summary", stats.writeSummary()),
	)

	return nil
}

type spliceStats struct {
	mu              sync.Mutex
	readBatchSizes  map[int]int
	writeBatchSizes map[int]int
}

func newSpliceStats() *spliceStats {
	return &spliceStats{
		readBatchSizes:  make(map[int]int),
		writeBatchSizes: make(map[int]int),
	}
}

func (s *spliceStats) recordReadBatch(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readBatchSizes[n]++
}

func (s *spliceStats) recordWriteBatch(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeBatchSizes[n]++
}

func (s *spliceStats) readSummary() batchSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return computeSummary(s.readBatchSizes)
}

func (s *spliceStats) writeSummary() batchSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return computeSummary(s.writeBatchSizes)
}

type batchSummary struct {
	TotalBatches int
	MinSize      int
	MaxSize      int
	AvgSize      float64
}

func computeSummary(hist map[int]int) batchSummary {
	if len(hist) == 0 {
		return batchSummary{}
	}

	var (
		totalCount int
		totalSize  int
		minSize    = int(^uint(0) >> 1) // Max int
		maxSize    int
	)

	for size, count := range hist {
		if size < minSize {
			minSize = size
		}
		if size > maxSize {
			maxSize = size
		}
		totalCount += count
		totalSize += size * count
	}

	return batchSummary{
		TotalBatches: totalCount,
		MinSize:      minSize,
		MaxSize:      maxSize,
		AvgSize:      float64(totalSize) / float64(totalCount),
	}
}
