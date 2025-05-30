package fasttun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Splice copies packets bidirectionally between two PacketQueues.
func Splice(ctx context.Context, qA, qB PacketQueue, mtu int) error {
	g, ctx := errgroup.WithContext(ctx)

	copyPackets := func(src, dst PacketQueue) error {
		pkts := make([][]byte, src.BatchSize())
		for i := range pkts {
			pkts[i] = make([]byte, mtu)
		}
		sizes := make([]int, src.BatchSize())
		toWrite := make([][]byte, src.BatchSize())

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

			toWrite = toWrite[:len(pkts)]
			for i := 0; i < n; i++ {
				toWrite[i] = pkts[i][:sizes[i]]
			}

			for len(toWrite) > 0 {
				written, err := dst.Write(toWrite)
				if err != nil {
					return fmt.Errorf("write error: %w", err)
				}
				toWrite = toWrite[written:]
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
