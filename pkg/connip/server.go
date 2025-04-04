package connip

import (
	"context"

	"github.com/dpeckett/network"
)

var _ TunnelTransport = (*ServerTransport)(nil)

type ServerConfig struct {
	// TODO: Define server configuration options
}

type ServerTransport struct {
	network.Network
}

func NewServerTransport(conf *ServerConfig) *ServerTransport {
	return &ServerTransport{}
}

func (t *ServerTransport) ListenForConnections(ctx context.Context) error {
	// TODO: Implement server listening logic

	// TODO: use splice to move packets around
	return nil
}

func (t *ServerTransport) Close() error {
	// TODO: Implement server closing logic
	return nil
}
