package wireguard

import (
	"io"
	"net/netip"

	"github.com/dpeckett/network"
)

// Network is an interface that represents a WireGuard network.
// It provides methods to manage peers, retrieve local addresses, and
// listen for incoming connections.
type Network interface {
	io.Closer
	network.Network
	// Peers returns known peers associated with the network.
	Peers() ([]PeerConfig, error)
	// AddPeer adds a new peer to the network.
	AddPeer(peerConf *PeerConfig) error
	// RemovePeer removes a peer from the network.
	RemovePeer(publicKey string) error
	// PublicKey returns the public key of this node.
	PublicKey() string
	// LocalAddresses returns the addresses associated with the node.
	LocalAddresses() ([]netip.Prefix, error)
	// ListenPort returns the local listen port of this node.
	ListenPort() (uint16, error)
}
