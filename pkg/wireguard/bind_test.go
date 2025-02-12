package wireguard_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/stunserver"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/netstack"
	"github.com/pion/ice/v4"
	icelogging "github.com/pion/logging"
	"github.com/pion/stun/v3"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/conn"
	"k8s.io/utils/ptr"
)

func TestICEBind(t *testing.T) {
	iceConf := &ice.AgentConfig{
		Urls: []*stun.URI{
			{
				Scheme: stun.SchemeTypeSTUN,
				Host:   "localhost",
				Port:   3478,
			},
		},
		NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4},
		CheckInterval: ptr.To(50 * time.Millisecond),
		CandidateTypes: []ice.CandidateType{
			ice.CandidateTypeHost,
			ice.CandidateTypeServerReflexive,
			ice.CandidateTypePeerReflexive,
			ice.CandidateTypeRelay,
		},
		LoggerFactory: &icelogging.DefaultLoggerFactory{
			Writer: log.NewDefaultLogWriter(log.InfoLevel),
		},
	}

	g, ctx := errgroup.WithContext(context.Background())

	// Local STUN server.
	g.Go(func() error {
		return stunserver.ListenAndServe(ctx, "localhost:3478")
	})

	offerFromController := make(chan *corev1alpha.ICEOffer)
	offerFromControlled := make(chan *corev1alpha.ICEOffer)

	// Controlling bind/peer.
	g.Go(func() error {
		bind := wireguard.NewIceBind(ctx, iceConf)
		defer func() {
			if err := bind.Close(); err != nil {
				t.Logf("error closing bind: %v", err)
			}
		}()

		peer, err := bind.NewPeer(true)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}

		peer.OnCandidate = func(c string) {
			ufrag, pwd := peer.LocalUserCredentials()
			cs := peer.LocalCandidates()

			offerFromController <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
		}

		if err := peer.Init(); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		remoteOffer := <-offerFromControlled

		if err := peer.AddRemoteOffer(remoteOffer); err != nil {
			return fmt.Errorf("failed to add remote offer: %w", err)
		}

		if err := peer.Connect(ctx, "controlled"); err != nil {
			return fmt.Errorf("failed to connect to controlled peer: %w", err)
		}

		ep, err := bind.ParseEndpoint("controlled")
		if err != nil {
			return fmt.Errorf("failed to parse endpoint: %w", err)
		}

		if err := bind.Send([][]byte{[]byte("hello")}, ep); err != nil {
			return fmt.Errorf("failed to send data: %w", err)
		}

		time.Sleep(1 * time.Second)

		return context.Canceled
	})

	// Controlled bind/peer.
	g.Go(func() error {
		bind := wireguard.NewIceBind(ctx, iceConf)
		defer func() {
			if err := bind.Close(); err != nil {
				t.Logf("error closing bind: %v", err)
			}
		}()

		peer, err := bind.NewPeer(false)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}

		peer.OnCandidate = func(c string) {
			ufrag, pwd := peer.LocalUserCredentials()
			cs := peer.LocalCandidates()

			offerFromControlled <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
		}

		if err := peer.Init(); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		remoteOffer := <-offerFromController

		if err := peer.AddRemoteOffer(remoteOffer); err != nil {
			return fmt.Errorf("failed to add remote offer: %w", err)
		}

		if err := peer.Connect(ctx, "controller"); err != nil {
			return fmt.Errorf("failed to connect to controller peer: %w", err)
		}

		receiveFns, _, err := bind.Open(0)
		if err != nil {
			return fmt.Errorf("failed to open bind: %w", err)
		}

		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()

		packets, err := receiveAllPackets(ctx, bind, receiveFns)
		if err != nil {
			return fmt.Errorf("failed to receive all packets: %w", err)
		}

		if len(packets) != 1 || string(packets[0]) != "hello" {
			return fmt.Errorf("expected 1 packet with content 'hello', got: %v", packets)
		}

		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}

// receiveAllPackets receives all packets from all receive functions until the
// context is canceled or the bind is closed.
func receiveAllPackets(ctx context.Context, bind conn.Bind, receiveFns []conn.ReceiveFunc) ([][]byte, error) {
	var packets [][]byte

	g, ctx := errgroup.WithContext(ctx)
	for _, receiveFn := range receiveFns {
		receiveFn := receiveFn
		g.Go(func() error {
			batchSize := bind.BatchSize()
			epsForBatch := make([]conn.Endpoint, batchSize)
			sizesForBatch := make([]int, batchSize)
			packetsForBatch := make([][]byte, batchSize)
			for i := 0; i < batchSize; i++ {
				packetsForBatch[i] = make([]byte, netstack.DefaultMTU)
			}

			for {
				select {
				case <-ctx.Done():
					return nil
				default:
				}

				n, err := receiveFn(packetsForBatch, sizesForBatch, epsForBatch)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						return fmt.Errorf("failed to receive packets: %w", err)
					}

					return nil
				}

				for i := 0; i < n; i++ {
					packet := make([]byte, sizesForBatch[i])
					copy(packet, packetsForBatch[i])
					packets = append(packets, packet)
				}
			}
		})
	}

	return packets, g.Wait()
}
