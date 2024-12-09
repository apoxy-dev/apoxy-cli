//go:build linux

// Package runc implements container runtime based on OpenContainers
// libcontainer package.
package runc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"syscall"

	"github.com/metal-stack/go-ipam"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/vishvananda/netns"

	// Required for runc to work.
	_ "github.com/opencontainers/runc/libcontainer/nsenter"

	"github.com/apoxy-dev/apoxy-cli/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

func init() {
	// If called with "init" arg, that's a call by the libcontainer.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		goruntime.GOMAXPROCS(1)
		goruntime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			log.Fatalf("Unable to start runc initialization: %v", err)
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

type Option func(*options)

type options struct {
	runtimeBinPath string
	baseDir        string
	hostIPv4CIDR   string
	hostIPv6CIDR   string
}

func defaultOptions() *options {
	return &options{
		runtimeBinPath: "edge-runtime",
		baseDir:        "/run/edgefuncs",
		hostIPv4CIDR:   "192.168.100.0/24",
		hostIPv6CIDR:   "fd00::/64",
	}
}

func WithRuntimeBinPath(p string) Option {
	return func(o *options) {
		o.runtimeBinPath = p
	}
}

func WithWorkDir(p string) Option {
	return func(o *options) {
		o.baseDir = p
	}
}

type runtime struct {
	ipamer                ipam.Ipamer
	runtimeBinPath        string
	stateDir, rootBaseDir string
	prefixIPv4            *ipam.Prefix
	prefixIPv6            *ipam.Prefix
}

func initIPAM(
	ctx context.Context,
	ipamer ipam.Ipamer,
	cidr string,
) (*ipam.Prefix, error) {
	// FYI: IPAM internals reload the storage on each operation.
	prefixIPv4, err := ipamer.PrefixFrom(ctx, cidr)
	if err != nil {
		if !errors.Is(err, ipam.ErrNotFound) {
			return nil, fmt.Errorf("failed to get prefix from ipam: %w", err)
		}

		if prefixIPv4, err = ipamer.NewPrefix(ctx, cidr); err != nil {
			return nil, fmt.Errorf("failed to create prefix in ipam: %w", err)
		}
	}
	// Acquire gateway (first IP + 1)
	network, err := prefixIPv4.Network()
	if err != nil {
		return nil, fmt.Errorf("failed to get network from prefix: %w", err)
	}
	gwIP := network.Next()
	if gwIP.IsUnspecified() {
		return nil, errors.New("failed to get gateway IP: network is too small: %v", network)
	}
	// If the gateway is already acquired, it will return a nil and no error.
	_, err = ipamer.AcquireSpecificIP(ctx, prefixIPv4.Cidr, gwIP.String())
	if err != nil {
		return nil, fmt.Errorf("failed to acquire gateway IP: %w", err)
	}

	return prefixIPv4, nil
}

// New returns a new edgefunc.Runtime implementation based on runc.
func New(ctx context.Context, opts ...Option) (edgefunc.Runtime, error) {
	runtimeOpts := defaultOptions()
	for _, o := range opts {
		o(runtimeOpts)
	}

	if err := os.MkdirAll(runtimeOpts.baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	ipamJson := filepath.Join(runtimeOpts.baseDir, "ipam.json")
	ipamer := ipam.NewWithStorage(ipam.NewLocalFile(ctx, ipamJson))
	prefixIPv4, err := initIPAM(ctx, ipamer, runtimeOpts.hostIPv4CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPAM: %w", err)
	}
	prefixIPv6, err := initIPAM(ctx, ipamer, runtimeOpts.hostIPv6CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPAM: %w", err)
	}

	return &runtime{
		ipamer:         ipamer,
		runtimeBinPath: runtimeOpts.runtimeBinPath,
		stateDir:       filepath.Join(runtimeOpts.baseDir, "state"),
		rootBaseDir:    filepath.Join(runtimeOpts.baseDir, "rootfs"),
		prefixIPv4:     prefixIPv4,
		prefixIPv6:     prefixIPv6,
	}, nil
}

func config(id, rootFS string) *configs.Config {
	devs := make([]*devices.Rule, len(specconv.AllowedDevices))
	for i, d := range specconv.AllowedDevices {
		devs[i] = &d.Rule
	}
	caps := []string{"CAP_NET_BIND_SERVICE"}
	c := &configs.Config{
		Labels:     []string{},
		Rootfs:     rootFS,
		Readonlyfs: true,
		Capabilities: &configs.Capabilities{
			Bounding:  caps,
			Effective: caps,
			Permitted: caps,
			Ambient:   caps,
		},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			{Type: configs.NEWNET, Path: fmt.Sprintf("/run/netns/%s", id)},
			// If we set new user namespace, the unprivileged user will not be able to
			// join the network namespace above due to it being created by the privileged
			// user currently.
			// TODO(dilyevsky): Need to create the network namespace in the unprivileged
			// user namespace to make this work.
			//{Type: configs.NEWUSER},
			{Type: configs.NEWCGROUP},
		}),
		Devices:  specconv.AllowedDevices,
		Hostname: "envoy",
		MaskPaths: []string{
			"/proc/kcore",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		NoNewKeyring: true,
		Networks: []*configs.Network{
			{
				Type:    "loopback",
				Address: "127.0.0.1/0",
				Gateway: "localhost",
			},
		},
		Cgroups: &configs.Cgroup{
			Name:   "envoy",
			Parent: "system",
			Resources: &configs.Resources{
				MemorySwappiness: nil,
				Devices:          devs,
			},
		},
		Mounts: []*configs.Mount{
			{
				Source:      "proc",
				Destination: "/proc",
				Device:      "proc",
				Flags:       syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV,
			},
			{
				Source:      "tmpfs",
				Destination: "/dev",
				Device:      "tmpfs",
				Flags:       syscall.MS_NOSUID | syscall.MS_STRICTATIME,
				Data:        "mode=755",
			},
			{
				Source:      "sysfs",
				Destination: "/sys",
				Device:      "sysfs",
				Flags:       syscall.MS_RDONLY | syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV,
			},
			// /etc and /lib are bind-mounted as read-only to avoid having to
			// unpack legit container images into rootfs. Binds are read-only
			// to avoid any potential fuckery from edgefunc jails.
			{
				Source:      "/etc",
				Destination: "/etc",
				Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
			},
			{
				Source:      "/lib",
				Destination: "/lib",
				Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
			},
		},
		//UidMappings: []configs.IDMap{
		//	{
		//		ContainerID: 0,
		//		HostID:      0,
		//		Size:        1,
		//	},
		//},
		//GidMappings: []configs.IDMap{
		//	{
		//		ContainerID: 0,
		//		HostID:      0,
		//		Size:        1,
		//	},
		//},
	}

	if _, err := os.Stat("/lib64"); err == nil {
		c.Mounts = append(c.Mounts, &configs.Mount{
			Source:      "/lib64",
			Destination: "/lib64",
			Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
		})
	}

	return c
}

func newNs(rid string) (netns.NsHandle, error) {
	// Need to lock OS thread bc netns is using thread-local data.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return netns.None(), fmt.Errorf("failed to get current netns: %v", err)
	}
	defer netns.Set(origns)

	return netns.NewNamed(rid)
}

// Start requests the runtime to start the execution of the function.
func (r *runtime) Start(ctx context.Context, id string, esZipPath string) error {
	h, err := newNs(id)
	if err != nil {
		return fmt.Errorf("failed to create netns: %v", err)
	}
	defer func() {
		if err := netns.DeleteNamed(id); err != nil {
			log.Errorf("failed to delete netns: %v", err)
		}
		h.Close()

	}()

	ipv4, err := r.ipamer.AcquireIP(ctx, r.prefixIPv4.Cidr)
	if err != nil {
		return fmt.Errorf("failed to acquire ipv4: %v", err)
	}

	if err := setupVeth(id, h, ipv4); err != nil {
		return fmt.Errorf("failed to setup veth pair: %v", err)
	}

	rootFS := filepath.Join(r.rootBaseDir, id)
	if err := os.MkdirAll(rootFS, 0755); err != nil {
		return fmt.Errorf("failed to create rootfs: %v", err)
	}
	cfg := config(id, rootFS)
	ctr, err := libcontainer.Create(r.stateDir, id, cfg)
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}
	args := []string{
		r.runtimeBinPath,
		"start",
		"/" + filepath.Base(esZipPath),
	}
	var extraArgs []string
	p := &libcontainer.Process{
		Args:   append(args, extraArgs...),
		User:   "root",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Init:   true,
	}

	if err := ctr.Run(p); err != nil {
		return fmt.Errorf("failed to run container: %v", err)
	}

	return nil
}

// Stop requests the runtime to stop the execution of the function.
func (r *runtime) Stop(ctx context.Context, id string) error {
	ctr, err := libcontainer.Load(r.stateDir, id)
	if err != nil {
		return fmt.Errorf("failed to load container: %v", err)
	}
	status, err := ctr.Status()
	if err != nil {
		return fmt.Errorf("failed to get container status: %v", err)
	}
	if status == libcontainer.Stopped {
		return nil
	}
	ps, err := ctr.Processes()
	if err != nil {
		return fmt.Errorf("failed to get container processes: %v", err)
	}
	for _, pid := range ps {
		p, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("failed to find process: %v", err)
		}

		log.Infof("sending SIGTERM to process %d", pid)

		if err := p.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}
	}
	return nil
}

func stateFromStatus(status libcontainer.Status) edgefunc.State {
	switch status {
	case libcontainer.Stopped:
		return edgefunc.StateStopped
	case libcontainer.Running:
		return edgefunc.StateRunning
	case libcontainer.Paused:
		return edgefunc.StatePaused
	default:
		return edgefunc.StateUnknown
	}
}

// Status returns the status of the function with the given id.
func (r *runtime) Status(ctx context.Context, id string) (edgefunc.Status, error) {
	ctr, err := libcontainer.Load(r.stateDir, id)
	if err != nil {
		return edgefunc.Status{}, fmt.Errorf("failed to load container: %v", err)
	}

	cStatus, err := ctr.Status()
	if err != nil {
		return edgefunc.Status{}, fmt.Errorf("failed to get container status: %v", err)
	}
	cState, err := ctr.State()
	if err != nil {
		return edgefunc.Status{}, fmt.Errorf("failed to get container state: %v", err)
	}

	return edgefunc.Status{
		ID:        id,
		State:     stateFromStatus(cStatus),
		CreatedAt: cState.Created,
	}, nil
}

// List returns a list of all functions running in the runtime.
func (r *runtime) List(ctx context.Context) ([]edgefunc.Status, error) {
	dir, err := os.ReadDir(r.stateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read state dir: %v", err)
	}
	if len(dir) == 0 {
		return nil, nil
	}

	statuses := make([]edgefunc.Status, 0, len(dir))
	for _, d := range dir {
		if !d.IsDir() {
			continue
		}

		ctr, err := libcontainer.Load(r.stateDir, d.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %v", err)
		}

		cStatus, err := ctr.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get container status: %v", err)
		}
		cState, err := ctr.State()
		if err != nil {
			return nil, fmt.Errorf("failed to get container state: %v", err)
		}

		statuses = append(statuses, edgefunc.Status{
			ID:        d.Name(),
			State:     stateFromStatus(cStatus),
			CreatedAt: cState.Created,
		})
	}

	return statuses, nil
}
