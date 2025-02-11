package stunserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/pion/stun"
)

func ListenAndServe(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("error setting up listener: %w", err)
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		if err := pc.Close(); err != nil {
			slog.Error("Error closing listener", slog.Any("error", err))
		}
	}()

	buf := make([]byte, 1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("error reading from listener: %w", err)
			}

			return nil
		}

		message := new(stun.Message)
		message.Raw = append([]byte{}, buf[:n]...)
		if err := message.Decode(); err != nil {
			return fmt.Errorf("error decoding STUN message: %w", err)
		}

		if err := handleSTUNMessage(message, addr, pc); err != nil {
			return fmt.Errorf("error handling STUN message: %w", err)
		}
	}
}

func handleSTUNMessage(message *stun.Message, addr net.Addr, conn net.PacketConn) error {
	if message.Type.Method == stun.MethodBinding && message.Type.Class == stun.ClassRequest {
		response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess,
			stun.XORMappedAddress{IP: addr.(*net.UDPAddr).IP, Port: addr.(*net.UDPAddr).Port},
			stun.MessageIntegrity([]byte("apoxy-stun-secret")),
			stun.Fingerprint,
		)

		if _, err := conn.WriteTo(response.Raw, addr); err != nil {
			return fmt.Errorf("error sending STUN response: %w", err)
		}
	}

	return nil
}
