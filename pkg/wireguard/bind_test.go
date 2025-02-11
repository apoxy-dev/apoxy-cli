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

	ctx := context.Background()

	g, ctx := errgroup.WithContext(ctx)

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

		peer, err := bind.NewPeer(ctx, true)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}

		peer.OnCandidate = func(c string) {
			t.Logf("controlling peer candidate: %s", c)

			ufrag, pwd := peer.LocalUserCredentials()
			cs := peer.LocalCandidates()

			offerFromController <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
		}

		if err := peer.Init(ctx); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		remoteOffer := <-offerFromControlled

		t.Logf("remote offer: %v", remoteOffer)

		if err := peer.AddRemoteOffer(remoteOffer); err != nil {
			return fmt.Errorf("failed to add remote offer: %w", err)
		}

		if err := peer.Connect(ctx, "controlled"); err != nil {
			return fmt.Errorf("failed to connect to controlled peer: %w", err)
		}

		t.Logf("connected")

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

		peer, err := bind.NewPeer(ctx, false)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}

		peer.OnCandidate = func(c string) {
			t.Logf("local candidate: %s", c)

			ufrag, pwd := peer.LocalUserCredentials()
			cs := peer.LocalCandidates()

			offerFromControlled <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
		}

		if err := peer.Init(ctx); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		receiveFns, _, err := bind.Open(0)
		if err != nil {
			return fmt.Errorf("failed to open bind: %w", err)
		}

		for _, receiveFn := range receiveFns {
			go func(receiveFn conn.ReceiveFunc) {
				batchSize := bind.BatchSize()
				eps := make([]conn.Endpoint, batchSize)
				sizes := make([]int, batchSize)
				packets := make([][]byte, batchSize)
				for i := 0; i < batchSize; i++ {
					packets[i] = make([]byte, 1500)
				}

				for {
					select {
					case <-ctx.Done():
						return
					default:
					}

					n, err := receiveFn(packets, sizes, eps)
					if err != nil {
						if !errors.Is(err, net.ErrClosed) {
							t.Logf("failed to receive packets: %v", err)
						}

						return
					}

					for i := 0; i < n; i++ {
						t.Logf("received: %s", string(packets[i]))
					}
				}
			}(receiveFn)
		}

		remoteOffer := <-offerFromController

		t.Logf("remote offer: %v", remoteOffer)

		if err := peer.AddRemoteOffer(remoteOffer); err != nil {
			return fmt.Errorf("failed to add remote offer: %w", err)
		}

		if err := peer.Connect(ctx, "controller"); err != nil {
			return fmt.Errorf("failed to connect to controller peer: %w", err)
		}

		t.Logf("connected")

		return context.Canceled
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
