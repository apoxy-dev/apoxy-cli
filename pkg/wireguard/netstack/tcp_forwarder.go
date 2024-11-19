package netstack

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/dpeckett/contextio"
	"github.com/dpeckett/triemap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/apoxy-dev/apoxy-cli/pkg/network"
)

type TCPForwarderConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// The network to forward connections to.
	Upstream network.Network
}

// TCPForwarder forwards TCP connections.
func TCPForwarder(ctx context.Context, conf *TCPForwarderConfig) func(ipstack *stack.Stack, req *tcp.ForwarderRequest) {
	allowedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.AllowedDestinations {
		allowedDestinations.Insert(prefix, struct{}{})
	}

	deniedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.DeniedDestinations {
		deniedDestinations.Insert(prefix, struct{}{})
	}

	allowedDestination := func(addr netip.Addr) bool {
		_, allowed := allowedDestinations.Get(addr)
		if allowed {
			if _, denied := deniedDestinations.Get(addr); denied {
				allowed = false
			}
		}
		return allowed
	}

	return func(ipstack *stack.Stack, req *tcp.ForwarderRequest) {
		reqDetails := req.ID()

		srcAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.RemoteAddress), reqDetails.RemotePort)
		dstAddrPort := netip.AddrPortFrom(addrFromNetstackIP(reqDetails.LocalAddress), reqDetails.LocalPort)

		logger := slog.With(
			slog.String("src", srcAddrPort.String()),
			slog.String("dst", dstAddrPort.String()))

		if !allowedDestination(dstAddrPort.Addr()) {
			logger.Warn("Dropping TCP session, destination is not allowed")
			req.Complete(true) // send RST
			return
		}

		go func() {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			logger.Debug("Forwarding session")
			defer logger.Debug("Session finished")

			var wq waiter.Queue
			ep, tcpipErr := req.CreateEndpoint(&wq)
			if tcpipErr != nil {
				logger.Warn("Failed to create local endpoint",
					slog.String("error", tcpipErr.String()))

				req.Complete(true) // send RST
				return
			}

			// Cancel the context when the connection is closed.
			waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
			wq.EventRegister(&waitEntry)
			defer wq.EventUnregister(&waitEntry)

			go func() {
				select {
				case <-ctx.Done():
				case <-notifyCh:
					cancel()
				}
			}()

			// Disable Nagle's algorithm.
			ep.SocketOptions().SetDelayOption(false)
			// Enable keep-alive to make detecting dead connections easier.
			ep.SocketOptions().SetKeepAlive(true)

			local := gonet.NewTCPConn(&wq, ep)
			defer local.Close()

			// Connect to the destination.
			remote, err := conf.Upstream.DialContext(ctx, "tcp", dstAddrPort.String())
			if err != nil {
				logger.Warn("Failed to dial destination", slog.Any("error", err))

				req.Complete(true) // send RST
				return
			}
			defer remote.Close()

			// Start forwarding.
			if _, err := contextio.SpliceContext(ctx, local, remote, nil); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("Failed to forward session", slog.Any("error", err))

				req.Complete(true) // send RST
				return
			}

			req.Complete(false) // send FIN
		}()
	}
}

func addrFromNetstackIP(ip tcpip.Address) netip.Addr {
	switch ip.Len() {
	case 4:
		ip := ip.As4()
		return netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	case 16:
		ip := ip.As16()
		return netip.AddrFrom16(ip).Unmap()
	}
	return netip.Addr{}
}
