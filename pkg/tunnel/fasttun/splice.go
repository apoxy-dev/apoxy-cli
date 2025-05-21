package fasttun

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"golang.org/x/sync/errgroup"
)

// Splice copies packets bidirectionally between two PacketQueues.
func Splice(ctx context.Context, qA, qB PacketQueue, batchSize, mtu int) error {
	g, ctx := errgroup.WithContext(ctx)

	// Create histograms for read and write operations
	var histMu sync.Mutex
	readHist := hdrhistogram.New(1, 1000000, 3) // 1us to 1s with 3 significant figures
	writeHist := hdrhistogram.New(1, 1000000, 3)

	copyPackets := func(src, dst PacketQueue, direction string) error {
		pkts := make([][]byte, batchSize)
		for i := range pkts {
			pkts[i] = make([]byte, mtu)
		}
		sizes := make([]int, batchSize)

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			readStart := time.Now()
			n, err := src.Read(pkts, sizes)
			readDuration := time.Since(readStart).Microseconds()

			// Record read time in histogram
			histMu.Lock()
			readHist.RecordValue(readDuration)
			histMu.Unlock()

			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}
			if n == 0 {
				continue
			}

			toWrite := make([][]byte, n)
			for i := 0; i < n; i++ {
				toWrite[i] = pkts[i][:sizes[i]]
			}

			written := 0
			writeStart := time.Now()
			for written < n {
				m, err := dst.Write(toWrite[written:])
				if err != nil {
					return fmt.Errorf("write error: %w", err)
				}
				written += m
			}
			writeDuration := time.Since(writeStart).Microseconds()

			// Record write time in histogram
			histMu.Lock()
			writeHist.RecordValue(writeDuration)
			histMu.Unlock()
		}
	}

	g.Go(func() error {
		return copyPackets(qA, qB, "A->B")
	})

	g.Go(func() error {
		return copyPackets(qB, qA, "B->A")
	})

	err := g.Wait()

	// Print the histograms on exit
	log.Printf("Read latency histogram (microseconds):")
	log.Printf("  Min: %d, Max: %d, Mean: %.2f",
		readHist.Min(), readHist.Max(), readHist.Mean())
	log.Printf("  p50: %d, p90: %d, p99: %d, p99.9: %d",
		readHist.ValueAtQuantile(50),
		readHist.ValueAtQuantile(90),
		readHist.ValueAtQuantile(99),
		readHist.ValueAtQuantile(99.9))

	log.Printf("Write latency histogram (microseconds):")
	log.Printf("  Min: %d, Max: %d, Mean: %.2f",
		writeHist.Min(), writeHist.Max(), writeHist.Mean())
	log.Printf("  p50: %d, p90: %d, p99: %d, p99.9: %d",
		writeHist.ValueAtQuantile(50),
		writeHist.ValueAtQuantile(90),
		writeHist.ValueAtQuantile(99),
		writeHist.ValueAtQuantile(99.9))

	if err != nil && !(errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "closed")) {
		return err
	}

	return nil
}
