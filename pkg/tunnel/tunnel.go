package tunnel

import (
	"io"
	"net/netip"

	"k8s.io/utils/set"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

var stunServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// Tunnel is a WireGuard tunnel.
type Tunnel interface {
	io.Closer
	// Peers returns the public keys of the peers in the tunnel.
	Peers() (set.Set[string], error)
	// AddPeer adds a new peer to the tunnel.
	AddPeer(peerConf *wireguard.PeerConfig) error
	// RemovePeer removes a peer from the tunnel.
	RemovePeer(publicKey string) error
	// PublicKey returns the public key of this end of the tunnel.
	PublicKey() string
	// ExternalAddress returns the external address of this end of the tunnel.
	ExternalAddress() netip.AddrPort
	// InternalAddress returns the internal address of this end of the tunnel.
	InternalAddress() netip.Prefix
	// ListenPort returns the local listen port of this end of the tunnel.
	ListenPort() uint16
}
