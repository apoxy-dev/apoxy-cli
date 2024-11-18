package uapi_test

import (
	"testing"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/uapi"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
)

func TestMarshal(t *testing.T) {
	t.Run("DeviceConfig", func(t *testing.T) {
		deviceConf := wireguard.DeviceConfig{
			PrivateKey:   ptr.To("cDnfzVc9fyfhmZx3rrUV4dxIAyBXUfYPy6deh/5W1VY="),
			ListenPort:   ptr.To(uint16(51820)),
			FirewallMark: ptr.To(uint32(32)),
		}

		marshalledDeviceConf, err := uapi.Marshal(deviceConf)
		require.NoError(t, err)

		expected := `private_key=7039dfcd573d7f27e1999c77aeb515e1dc4803205751f60fcba75e87fe56d556
listen_port=51820
fwmark=32
`

		require.Equal(t, expected, marshalledDeviceConf)
	})

	t.Run("PeerConfig", func(t *testing.T) {
		peerConf := wireguard.PeerConfig{
			PublicKey:                      ptr.To("h2KkEoaek0fAD1V28FsxqbVTRiJ7fo8zGDsoHDp6Jhk="),
			PresharedKey:                   ptr.To("WCWTIPrZ2zeOrceY1SuLsLKy8h8QYTzhq/Ef06AYMcw="),
			Endpoint:                       ptr.To("1.1.1.1:51820"),
			PersistentKeepaliveIntervalSec: ptr.To(uint16(25)),
			AllowedIPs:                     []string{"10.0.0.1/32", "fddd:b465:b380::1/128"},
		}

		marshalledPeerConf, err := uapi.Marshal(peerConf)
		require.NoError(t, err)

		expected := `public_key=8762a412869e9347c00f5576f05b31a9b55346227b7e8f33183b281c3a7a2619
preshared_key=58259320fad9db378eadc798d52b8bb0b2b2f21f10613ce1abf11fd3a01831cc
endpoint=1.1.1.1:51820
persistent_keepalive_interval=25
allowed_ip=10.0.0.1/32
allowed_ip=fddd:b465:b380::1/128
`

		require.Equal(t, expected, marshalledPeerConf)
	})
}
