package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"

	"github.com/dgraph-io/badger/v4"
	"github.com/metal-stack/go-ipam"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/apoxy-dev/apoxy-cli/pkg/edgefunc/runc/network/iptables"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	mtuSize         = 1500
	routeTableIndex = 100
)

type Option func(*Network)

func WithIpamDBPath(path string) Option {
	return func(n *Network) {
		n.ipamDBPath = path
	}
}

// WithSubnetPrefixSize sets the prefix size of the network.
func WithSubnetPrefixSize(prefixSize int) Option {
	return func(n *Network) {
		n.subnetPrefixSize = prefixSize
	}
}

// WithCIDR sets the cidr of the network.
func WithCIDR(cidr string) Option {
	return func(n *Network) {
		n.cidr = cidr
	}
}

// WithExtIfc sets the external interface name.
func WithExtIfc(name string) Option {
	return func(n *Network) {
		n.extIfName = name
	}
}

func defaultNetworkOptions() []Option {
	return []Option{
		WithCIDR("192.168.0.0/16"),
		WithSubnetPrefixSize(30),
		WithIpamDBPath("/var/lib/apoxy/ipam.db"),
		WithExtIfc("eth0"),
	}
}

// Network represents an execution container network.
type Network struct {
	// cidr of a parent network which is shared by all execution containers.
	cidr string
	// Size of a container network prefix to be allocated from the parent network.
	subnetPrefixSize int
	// ipamDBPath is the path to the ipam database.
	ipamDBPath string
	// External interface name.
	extIfName string

	db     *badger.DB
	ipamer ipam.Ipamer
}

// NewNetwork creates a new network.
func NewNetwork(opts ...Option) *Network {
	n := &Network{}
	for _, opt := range append(defaultNetworkOptions(), opts...) {
		opt(n)
	}
	return n
}

func (n *Network) loadFromDB(ctx context.Context) error {
	n.ipamer = ipam.NewWithStorage(NewBadgerStorage(n.db))

	var (
		cidr       string
		prefixSize int
	)
	if err := n.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("network"))
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return item.Value(func(val []byte) error {
			var net struct {
				Cidr             string `json:"cidr"`
				SubnetPrefixSize int    `json:"subnetPrefixSize"`
			}
			if err := json.Unmarshal(val, &net); err != nil {
				return err
			}
			cidr = net.Cidr
			prefixSize = net.SubnetPrefixSize
			return nil
		})
	}); err != nil {
		return fmt.Errorf("failed to get network from db: %w", err)
	}

	// Save new network if it doesn't exist
	if cidr == "" {
		cidr = n.cidr
		prefixSize = n.subnetPrefixSize
		if err := n.db.Update(func(txn *badger.Txn) error {
			net := struct {
				Cidr             string `json:"cidr"`
				SubnetPrefixSize int    `json:"subnetPrefixSize"`
			}{
				Cidr:             cidr,
				SubnetPrefixSize: prefixSize,
			}
			val, err := json.Marshal(net)
			if err != nil {
				return err
			}
			return txn.Set([]byte("network"), val)
		}); err != nil {
			return fmt.Errorf("failed to save network to db: %w", err)
		}

		if _, err := n.ipamer.NewPrefix(ctx, cidr); err != nil {
			return fmt.Errorf("failed to create ipam namespace: %w", err)
		}
	}

	// TODO(dilyevsky): migrate containers from old network to new one.
	if n.cidr != cidr {
		return fmt.Errorf("cidr mismatch: expected %s, got %s", n.cidr, cidr)
	}
	if n.subnetPrefixSize != prefixSize {
		return fmt.Errorf("prefix size mismatch: expected %d, got %d", n.subnetPrefixSize, prefixSize)
	}

	return nil
}

// Init performs the network initialization.
// Must be called before any other method
func (n *Network) Init(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(n.ipamDBPath), 0755); err != nil {
		return fmt.Errorf("failed to create ipam db directory: %w", err)
	}
	var err error
	n.db, err = badger.Open(badger.DefaultOptions(n.ipamDBPath))
	if err != nil {
		return fmt.Errorf("failed to open ipam db: %w", err)
	}

	if err := n.loadFromDB(ctx); err != nil {
		return fmt.Errorf("failed to load network from db: %w", err)
	}

	// Setup routing rule for routeTableIndex.
	log.Debugf("Setting up routing rule for table %d", routeTableIndex)
	rule := netlink.NewRule()
	rule.Table = routeTableIndex
	rule.Priority = 100
	rule.Src = &net.IPNet{
		IP:   net.ParseIP("0.0.0.0"),
		Mask: net.CIDRMask(0, 32),
	}
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("failed to add routing rule: %w", err)
	}

	log.Infof("Setting up container NAT")
	if err := iptables.SetupContainerNAT(n.extIfName); err != nil {
		return fmt.Errorf("failed to setup container NAT: %w", err)
	}

	return nil
}

func (n *Network) String() string {
	return fmt.Sprintf("Network(%s)", n.cidr)
}

func nsForCID(cid string) (netns.NsHandle, error) {
	// Need to lock OS thread bc netns is using thread-local data.
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()

	h, err := netns.GetFromName(cid)
	if err == nil {
		return h, nil
	}

	origns, err := netns.Get()
	if err != nil {
		return netns.None(), fmt.Errorf("failed to get current netns: %v", err)
	}
	defer netns.Set(origns)

	return netns.NewNamed(cid)
}

type sandboxRoute struct {
	Dst   string `json:"dst"`
	Table int    `json:"table"`
}

type sandboxInfo struct {
	Veth   string         `json:"veth"`
	Cidr   string         `json:"cidr"`
	Routes []sandboxRoute `json:"routes"`
}

// Up sets up the network for the given container.
func (n *Network) Up(ctx context.Context, cid string) error {
	// Check if the cid is already up.
	var up bool
	if err := n.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(cid))
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if item != nil {
			up = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to check cid: %w", err)
	}
	if up {
		log.Infof("cid %s is already up", cid)
		return nil
	}

	ns, err := nsForCID(cid)
	if err != nil {
		return fmt.Errorf("failed to create netns: %v", err)
	}

	v4prefix, err := n.ipamer.AcquireChildPrefix(ctx, n.cidr, uint8(n.subnetPrefixSize))
	if err != nil {
		return fmt.Errorf("failed to acquire ipv4: %v", err)
	}

	info := &sandboxInfo{
		Cidr: v4prefix.String(),
	}

	if err := setUpVeth(cid, ns, info); err != nil {
		return fmt.Errorf("failed to setup veth pair: %v", err)
	}

	// Save cid info to the db
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal cid info: %w", err)
	}
	if err := n.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(cid), []byte(infoJSON))
	}); err != nil {
		return fmt.Errorf("failed to save cid to db: %w", err)
	}

	return nil
}

// Down tears down the network for the given container.
func (n *Network) Down(ctx context.Context, cid string) error {
	ns, err := nsForCID(cid)
	if err != nil {
		return fmt.Errorf("failed to get netns: %w", err)
	}

	// Load cid network info from the db
	info := &sandboxInfo{}
	if err := n.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(cid))
		if err != nil {
			return err
		}
		if err := item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, info); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to get cidr from db: %w", err)
	}

	if err := tearDownVeth(info); err != nil {
		return fmt.Errorf("failed to tear down veth pair: %v", err)
	}

	// Release prefix from the ipam.
	prefix, err := n.ipamer.PrefixFrom(ctx, info.Cidr)
	if err != nil {
		return fmt.Errorf("failed to get prefix: %v", err)
	}
	if err := n.ipamer.ReleaseChildPrefix(ctx, prefix); err != nil {
		return fmt.Errorf("failed to release prefix: %v", err)
	}

	if err := ns.Close(); err != nil {
		return fmt.Errorf("failed to close netns: %w", err)
	}

	// Delete cid network info from the db
	if err := n.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(cid))
	}); err != nil {
		return fmt.Errorf("failed to delete cid from db: %w", err)
	}

	return nil
}

func ethName(prefix, cid string) string {
	h := fnv.New32a()
	h.Write([]byte(cid))
	n := prefix + fmt.Sprintf("%x", h.Sum32())
	if len(n) > netlink.IFNAMSIZ-1 {
		n = n[:netlink.IFNAMSIZ-1]
	}
	return n
}

func setupContainerVeth(cethName string, h netns.NsHandle, v4addr, v4gw netip.Addr, v4prefix netip.Prefix) error {
	ceth, err := netlink.LinkByName(cethName)
	if err != nil {
		return fmt.Errorf("failed to get ceth: %w", err)
	}

	// Move the container side of the veth pair into the container's netns.
	if err := netlink.LinkSetNsFd(ceth, int(h)); err != nil {
		return fmt.Errorf("failed to move ceth into container netns: %w", err)
	}

	nh, err := netlink.NewHandleAt(h)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer nh.Close()

	// Rename to eth0.
	if err := nh.LinkSetName(ceth, "eth0"); err != nil {
		return fmt.Errorf("failed to rename ceth: %w", err)
	}
	eth0, err := nh.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to get eth0: %w", err)
	}

	if err := nh.AddrAdd(eth0, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   v4addr.AsSlice(),
			Mask: net.CIDRMask(v4prefix.Bits(), 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add addr to veth: %w", err)
	}

	// Bring up the container side of the veth pair.
	if err := nh.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("failed to bring up veth: %w", err)
	}

	// Up the loopback interface while we're at it.
	lo, err := nh.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface: %w", err)
	}
	if err := nh.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to bring up loopback interface: %w", err)
	}

	if err := nh.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        v4gw.AsSlice(),
	}); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

func setUpVeth(cid string, h netns.NsHandle, info *sandboxInfo) error {
	// Create the veth pair.
	vp := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ethName("v", cid),
			MTU:  mtuSize,
		},
		PeerName: ethName("c", cid),
	}
	log.Infof("Creating veth pair %s <-> %s", vp.Name, vp.PeerName)
	if err := netlink.LinkAdd(vp); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	v4prefix, err := netip.ParsePrefix(info.Cidr)
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %w", err)
	}
	// For IPv4 default GW needs to be set to the first IP in the subnet.
	v4gw := v4prefix.Addr().Next()
	if !v4gw.IsValid() {
		return fmt.Errorf("invalid v4 gw: %s", v4gw)
	}
	// Container address is the second IP in the subnet.
	v4 := v4gw.Next()
	if !v4.IsValid() {
		return fmt.Errorf("invalid v4 addr: %s", v4)
	}

	if err := setupContainerVeth(vp.PeerName, h, v4, v4gw, v4prefix); err != nil {
		return fmt.Errorf("failed to setup container veth: %w", err)
	}

	veth, err := netlink.LinkByName(vp.Name)
	if err != nil {
		return fmt.Errorf("failed to get veth: %w", err)
	}
	log.Infof("Bringing up veth %s", vp.Name)
	// Bring up the host side of the veth pair.
	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to bring up veth: %w", err)
	}
	info.Veth = vp.Name

	// Set container gateway IP on the host side of the veth pair.
	log.Infof("Setting veth %s IP to %s", vp.Name, v4gw)
	if err := netlink.AddrAdd(veth, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   v4gw.AsSlice(),
			Mask: net.CIDRMask(32, 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add addr to veth: %w", err)
	}

	// Add host-scope route - this will direct all packets addressed to the container's
	// default IP to the veth pair.
	// TODO(dilyevsky): IPv6.
	log.Infof("Adding route for %s via %s", v4gw, vp.Name)
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: veth.Attrs().Index,
		Scope:     netlink.SCOPE_HOST,
		Dst: &net.IPNet{
			IP:   v4.AsSlice(),
			Mask: net.CIDRMask(32, 32),
		},
		Table: routeTableIndex,
	}); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	info.Routes = append(info.Routes, sandboxRoute{
		Dst:   v4.String(),
		Table: routeTableIndex,
	})

	return nil
}

func tearDownVeth(info *sandboxInfo) error {
	log.Infof("Removing veth pair for %s", info.Veth)
	veth, err := netlink.LinkByName(info.Veth)
	if err == nil {
		// Deleting one end of the veth pair automatically deletes the other end.
		if err := netlink.LinkDel(veth); err != nil {
			return fmt.Errorf("failed to delete veth pair: %w", err)
		}
	}

	log.Infof("Removing routes for %s", info.Veth)
	for _, r := range info.Routes {
		if err := netlink.RouteDel(&netlink.Route{
			LinkIndex: veth.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst: &net.IPNet{
				IP:   net.ParseIP(r.Dst),
				Mask: net.CIDRMask(32, 32),
			},
			Table: r.Table,
		}); err != nil && !errors.As(err, &netlink.LinkNotFoundError{}) {
			return fmt.Errorf("failed to delete route: %w", err)
		}
	}

	return nil
}
