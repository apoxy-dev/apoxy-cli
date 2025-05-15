package connection_test

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
)

func TestPipeThroughput(t *testing.T) {
	const (
		packetSize = netstack.IPv6MinMTU
		numPackets = 10_000_000
	)

	p1, p2 := connection.NewPipe(t.Context(), packetSize)

	payload := bytes.Repeat([]byte("X"), packetSize)
	buf := make([]byte, packetSize)

	var bytesTransferred int64
	var packetsTransferred int64

	// Reader goroutine
	go func() {
		for i := 0; i < numPackets; i++ {
			if _, err := p2.ReadPacket(buf); err != nil {
				select {
				case <-t.Context().Done():
				default:
					t.Fatalf("Read error: %v", err)
				}
				return
			}
			atomic.AddInt64(&bytesTransferred, int64(packetSize))
			atomic.AddInt64(&packetsTransferred, 1)
		}
	}()

	// Reporter goroutine
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func(startTime time.Time) {
		lastTransferred := int64(0)
		for range ticker.C {
			currentTransferred := atomic.LoadInt64(&bytesTransferred)
			bytesThisSecond := currentTransferred - lastTransferred
			lastTransferred = currentTransferred

			throughputGbps := (float64(bytesThisSecond*8) / 1e9)
			elapsed := time.Since(startTime).Truncate(time.Second)
			t.Logf("[+%s] Throughput: %.2f Gbps", elapsed, throughputGbps)
			t.Logf("[+%s] Packets: %d", elapsed, atomic.LoadInt64(&packetsTransferred))
		}
	}(time.Now())

	start := time.Now()

	// Writer loop
	for i := 0; i < numPackets; i++ {
		if _, err := p1.WritePacket(payload); err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)

	totalThroughputGbps := (float64(packetSize*numPackets*8) / 1e9) / duration.Seconds()
	t.Logf("Total Throughput: %.2f Gbps", totalThroughputGbps)
}
