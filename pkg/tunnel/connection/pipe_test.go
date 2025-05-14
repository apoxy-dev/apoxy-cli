package connection_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
)

func TestPipeThroughput(t *testing.T) {
	const (
		packetSize = 1024      // 1 KB per packet
		numPackets = 1_000_000 // Total packets to send
	)

	p1, p2 := connection.NewPipe(t.Context())

	payload := bytes.Repeat([]byte("X"), packetSize)
	buf := make([]byte, packetSize)

	done := make(chan struct{})

	go func() {
		for i := 0; i < numPackets; i++ {
			if _, err := p2.ReadPacket(buf); err != nil {
				t.Fatal(err)
			}
		}
		close(done)
	}()

	start := time.Now()

	for i := 0; i < numPackets; i++ {
		if _, err := p1.WritePacket(payload); err != nil {
			t.Fatal(err)
		}
	}

	<-done
	duration := time.Since(start)

	throughputGbps := (float64(packetSize*numPackets*8) / 1e9) / duration.Seconds()
	t.Logf("Sent %d packets of %d bytes in %s", numPackets, packetSize, duration)
	t.Logf("Throughput: %.2f Gbps", throughputGbps)
}
