// dial-stdio provides a dialer that connects to the standard I/O streams.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

var cmd = &cobra.Command{
	Use:   "dial-stdio",
	Short: "Dialer for standard I/O streams",
	Long:  "Dialer for standard I/O streams.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Disable()

		addr := args[0]

		// Parse network from addr scheme and dial out.
		var network string
		switch {
		case strings.HasPrefix(addr, "tcp://"):
			network = "tcp"
			addr = strings.TrimPrefix(addr, "tcp://")
		case strings.HasPrefix(addr, "udp://"):
			network = "udp"
			addr = strings.TrimPrefix(addr, "udp://")
		default:
			return fmt.Errorf("unsupported network scheme: %s", addr)
		}
		conn, err := net.Dial(network, addr)
		if err != nil {
			return fmt.Errorf("unable to dial %s: %w", addr, err)
		}
		defer conn.Close()

		// Copy standard I/O streams to the connection.
		done := make(chan struct{})
		go func() {
			io.Copy(conn, os.Stdin)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(os.Stdout, conn)
			done <- struct{}{}
		}()

		// Wait for either side to close the connection.
		select {
		case <-done:
		case <-cmd.Context().Done():
		}

		return nil
	},
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
