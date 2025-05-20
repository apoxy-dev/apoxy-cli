package fasttun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Splice copies packets bidirectionally between two PacketQueues.
func Splice(ctx context.Context, qA, qB PacketQueue, batchSize, mtu int) error {
	g, ctx := errgroup.WithContext(ctx)

	copyPackets := func(src, dst PacketQueue) error {
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

			n, err := src.Read(pkts, sizes)
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
			for written < n {
				m, err := dst.Write(toWrite[written:])
				if err != nil {
					return fmt.Errorf("write error: %w", err)
				}
				written += m
			}
		}
	}

	g.Go(func() error {
		return copyPackets(qA, qB)
	})

	g.Go(func() error {
		return copyPackets(qB, qA)
	})

	if err := g.Wait(); err != nil && !(errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "closed")) {
		return err
	}

	return nil
}
