package tunnel

import (
	"io"
	"net/netip"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

// Tunnel is a WireGuard tunnel.
type Tunnel interface {
	io.Closer
	// Peers returns the public keys of the peers in the tunnel.
	Peers() ([]wireguard.PeerConfig, error)
	// AddPeer adds a new peer to the tunnel.
	AddPeer(peerConf *wireguard.PeerConfig) error
	// RemovePeer removes a peer from the tunnel.
	RemovePeer(publicKey string) error
	// PublicKey returns the public key of this end of the tunnel.
	PublicKey() string
	// InternalAddress returns the internal address of this end of the tunnel.
	InternalAddress() netip.Prefix
	// ListenPort returns the local listen port of this end of the tunnel.
	ListenPort() (uint16, error)
}
