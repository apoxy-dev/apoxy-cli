package connip

import (
	"io"

	"github.com/dpeckett/network"
)

type TunnelTransport interface {
	io.Closer
	network.Network
}
