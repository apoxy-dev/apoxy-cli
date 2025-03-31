package wireguard

// DeviceConfig represents the configuration of a WireGuard device.
// This is the [Interface] section of a wg-quick(8) compatible INI configuration file.
type DeviceConfig struct {
	// Private key (base64). "0" indicates removal in set operations.
	PrivateKey *string `ini:"PrivateKey" uapi:"private_key,hex"`
	// Listening port in decimal-string format.
	ListenPort *uint16 `ini:"ListenPort" uapi:"listen_port"`
	// Decimal-string integer for fwmark. Zero indicates removal in set operations.
	FirewallMark *uint32 `ini:"FwMark" uapi:"fwmark"`
	// Only for set operations; true means subsequent peers replace existing ones.
	ReplacePeers *bool `uapi:"replace_peers"`

	// wg-quick specific fields.
	// Comma-separated list of IP (v4 or v6) addresses with CIDR to assign to the interface.
	Address []string `ini:"Address"`
	// Comma-separated list of DNS IPs or non-IP DNS search domains.
	DNS []string `ini:"DNS"`
	// Optional MTU; if unset, system automatically determines it.
	MTU *int `ini:"MTU"`
	// Controls the routing table; "off" disables routes, "auto" is default.
	Table *string `ini:"Table"`
	// Commands executed before the interface is up. Can be specified multiple times.
	PreUp []string `ini:"PreUp"`
	// Commands executed after the interface is up. Can be specified multiple times.
	PostUp []string `ini:"PostUp"`
	// Commands executed before the interface is down. Can be specified multiple times.
	PreDown []string `ini:"PreDown"`
	// Commands executed after the interface is down. Can be specified multiple times.
	PostDown []string `ini:"PostDown"`

	// Apoxy specific fields.
	// Packet capture file to write to (only supported in userspace mode).
	PacketCapturePath string
	// Verbose logging.
	Verbose *bool
}

// PeerConfig represents the configuration of a WireGuard peer.
// This is the [Peer] section of a wg-quick(8) compatible INI configuration file.
type PeerConfig struct {
	// Public key (base64). Unique within a message; not repeated.
	PublicKey *string `ini:"PublicKey" uapi:"public_key,hex"`
	// Preshared key (base64), "0" removes it in set operations.
	PresharedKey *string `ini:"PresharedKey" uapi:"preshared_key,hex"`
	// Endpoint in IP:port format (IPv4) or [IP]:port format (IPv6).
	Endpoint *string `ini:"Endpoint" uapi:"endpoint"`
	// Keepalive interval; 0 disables it.
	PersistentKeepaliveIntervalSec *uint16 `ini:"PersistentKeepalive" uapi:"persistent_keepalive_interval"`
	// IP/cidr for allowed IPs for this peer.
	AllowedIPs []string `ini:"AllowedIPs" uapi:"allowed_ip"`
	// Only for set operations; true means allowed IPs replace existing ones.
	ReplaceAllowedIPs *bool `uapi:"replace_allowed_ips"`
	// Only for set operations; true removes the previously added peer.
	Remove *bool `uapi:"remove"`
	// Only for set operations; true restricts changes to existing peers only.
	UpdateOnly *bool `uapi:"update_only"`

	// Fields valid only in get operations
	// Number of received bytes.
	RxBytes *uint64 `uapi:"rx_bytes"`
	// Number of transmitted bytes.
	TxBytes *uint64 `uapi:"tx_bytes"`
	// Seconds since Unix epoch of last handshake.
	LastHandshakeTimeSec *uint64 `uapi:"last_handshake_time_sec"`
	// Nanoseconds since Unix epoch of last handshake.
	LastHandshakeTimeNSec *uint64 `uapi:"last_handshake_time_nsec"`
}
