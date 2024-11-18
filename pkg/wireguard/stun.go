package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/stun"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/conn"
)

const defaultSTUNTimeout = 5 * time.Second

var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
}

// TrySTUN tries to resolve the external IP address and port of the host by
// sending a STUN request to the specified STUN servers.
func TryStun(ctx context.Context, bind conn.Bind, srcPort uint16, stunServers ...string) (netip.AddrPort, error) {
	slog.Debug("Attempting STUN resolution", slog.Any("servers", stunServers))

	// Use the original deadline if it exists, otherwise use a conservative timeout.
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); ok {
		ctx, cancel = context.WithCancel(ctx)
	} else {
		ctx, cancel = context.WithTimeout(ctx, defaultSTUNTimeout)
	}
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	receiveFns, _, err := bind.Open(srcPort)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to bind to port: %w", err)
	}

	g.Go(func() error {
		<-ctx.Done()
		if err := bind.Close(); err != nil {
			return err
		}
		return ctx.Err()
	})

	receivedPackets := make(map[string]chan []byte)
	var receivedPacketsMu sync.Mutex

	for _, receiveFn := range receiveFns {
		g.Go(func(receiveFn conn.ReceiveFunc) func() error {
			return func() error {
				batchSize := bind.BatchSize()
				packets := make([][]byte, batchSize)
				sizes := make([]int, batchSize)
				endpoints := make([]conn.Endpoint, batchSize)

				for i := 0; i < batchSize; i++ {
					// STUN responses will never be fragmented.
					packets[i] = make([]byte, 1500)
				}

				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}

					n, err := receiveFn(packets, sizes, endpoints)
					if err != nil {
						if !errors.Is(err, net.ErrClosed) {
							return fmt.Errorf("failed to receive packets: %w", err)
						}

						return nil
					}

					for i := 0; i < n; i++ {
						if sizes[i] == 0 {
							continue
						}

						pkt := make([]byte, sizes[i])
						copy(pkt, packets[i][:sizes[i]])
						if ch, ok := receivedPackets[endpoints[i].DstToString()]; ok {
							ch <- pkt
						}
					}
				}
			}
		}(receiveFn))
	}

	var addrPorts []netip.AddrPort
	var addrPortsMu sync.Mutex

	// Send STUN requests to all servers in parallel.
	for _, serverAddr := range stunServers {
		g.Go(func(serverAddr string) func() error {
			return func() error {
				uAddr, err := net.ResolveUDPAddr("udp", serverAddr)
				if err != nil {
					return fmt.Errorf("failed to resolve STUN server address: %w", err)
				}

				// Parse the STUN server endpoint
				ep, err := bind.ParseEndpoint(uAddr.AddrPort().String())
				if err != nil {
					return fmt.Errorf("failed to parse STUN server endpoint: %w", err)
				}

				// Build the STUN binding request message
				m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

				// Set up a channel to receive the STUN response
				ch := make(chan []byte, 1)
				receivedPacketsMu.Lock()
				receivedPackets[ep.DstToString()] = ch
				receivedPacketsMu.Unlock()
				defer func() {
					receivedPacketsMu.Lock()
					delete(receivedPackets, ep.DstToString())
					receivedPacketsMu.Unlock()
					close(ch)
				}()

				// Send the STUN request
				if sendErr := bind.Send([][]byte{m.Raw}, ep); sendErr != nil {
					return fmt.Errorf("failed to send STUN request to %s: %w", serverAddr, sendErr)
				}

				// Wait for the STUN response
				select {
				case <-ctx.Done():
					return ctx.Err()
				case pkt := <-ch:
					// Parse the STUN response
					if stun.IsMessage(pkt) {
						resp := &stun.Message{Raw: pkt}
						if err := resp.Decode(); err != nil {
							slog.Error("Failed to decode STUN server message", slog.Any("error", err))
						}

						if resp.Type.Method == stun.MethodBinding && resp.Type.Class == stun.ClassSuccessResponse {
							var xorAddr stun.XORMappedAddress
							if err := xorAddr.GetFrom(resp); err != nil {
								return fmt.Errorf("failed to get XOR-MAPPED-ADDRESS from STUN server message: %w", err)
							}

							addr, ok := netip.AddrFromSlice(xorAddr.IP[:])
							if !ok {
								return errors.New("failed to parse XOR-MAPPED-ADDRESS IP")
							}

							addrPortsMu.Lock()
							addrPorts = append(addrPorts, netip.AddrPortFrom(addr, uint16(xorAddr.Port)))
							completed := len(addrPorts) == len(stunServers)
							addrPortsMu.Unlock()

							if completed {
								// Shutdown the receive goroutines and allow the errgroup to exit.
								cancel()
							}
						} else {
							return errors.New("unexpected STUN response")
						}
					}
				}

				return nil
			}
		}(serverAddr))
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return netip.AddrPort{}, fmt.Errorf("STUN resolution failed: %w", err)
	}

	// Make sure the external address is stable.
	addrPort := addrPorts[0]
	if len(addrPorts) > 1 {
		for _, ap := range addrPorts {
			if ap != addrPort {
				return netip.AddrPort{}, errors.New("public address is not stable")
			}
		}
	}

	slog.Debug("STUN resolution succeeded", slog.Any("address", addrPort))

	return addrPort, nil
}
