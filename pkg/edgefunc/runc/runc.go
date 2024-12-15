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
	"golang.org/x/sys/unix"
	"k8s.io/utils/ptr"

	// Enable cgroup manager to manage devices
	_ "github.com/opencontainers/runc/libcontainer/cgroups/devices"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"

	"github.com/apoxy-dev/apoxy-cli/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		// This is the golang entry point for runc init, executed
		// before main() but after libcontainer/nsenter's nsexec().
		libcontainer.Init()
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
		runtimeBinPath: "/bin/edge-runtime",
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
	log.Infof("Initializing IPAM with cidr %s", cidr)
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
		return nil, fmt.Errorf("failed to get gateway IP: network is too small: %v", network)
	}
	// If the gateway is already acquired, it will return a nil and no error.
	_, err = ipamer.AcquireSpecificIP(ctx, prefixIPv4.Cidr, gwIP.String())
	if err != nil {
		return nil, fmt.Errorf("failed to acquire gateway IP: %w", err)
	}

	return prefixIPv4, nil
}

// NewRuntime returns a new edgefunc.Runtime implementation based on runc.
func NewRuntime(ctx context.Context, opts ...Option) (edgefunc.Runtime, error) {
	runtimeOpts := defaultOptions()
	for _, o := range opts {
		o(runtimeOpts)
	}

	log.Infof("Creating edge-runtime container runtime...")
	log.Infof("Initializing state dirs...")

	if err := os.MkdirAll(runtimeOpts.baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}
	stateDir := filepath.Join(runtimeOpts.baseDir, "state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	rootBaseDir := filepath.Join(runtimeOpts.baseDir, "rootfs")
	if err := os.MkdirAll(rootBaseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rootFS directory: %w", err)
	}

	if _, err := os.Stat(runtimeOpts.runtimeBinPath); err != nil {
		fmt.Errorf("edge-runtime binary not found at %s", runtimeOpts.runtimeBinPath)
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
		stateDir:       stateDir,
		rootBaseDir:    rootBaseDir,
		prefixIPv4:     prefixIPv4,
		prefixIPv6:     prefixIPv6,
	}, nil
}

func config(id, rootFS, runtimeBinPath, esZipPath string) *configs.Config {
	devs := make([]*devices.Rule, len(specconv.AllowedDevices))
	for i, d := range specconv.AllowedDevices {
		devs[i] = &d.Rule
	}
	caps := []string{"CAP_NET_BIND_SERVICE"}
	c := &configs.Config{
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
		Hostname: "edge-runtime",
		MaskPaths: []string{
			"/proc/kcore",
			"/sys/firmware",
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
			Name:   "edge-runtime",
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
			{
				Source:      "cgroup",
				Destination: "/sys/fs/cgroup",
				Device:      "cgroup",
				Flags:       syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_RELATIME | syscall.MS_RDONLY,
			},
			{
				Source:      "devpts",
				Destination: "/dev/pts",
				Device:      "devpts",
				Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
				Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			},
			{
				Source:      "/lib",
				Destination: "/lib",
				Device:      "bind",
				Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
			},
			{
				Source:      "tmpfs",
				Destination: "/tmp",
				Device:      "tmpfs",
				Flags:       syscall.MS_NOSUID | syscall.MS_STRICTATIME,
				Data:        "mode=1777,size=100M",
			},
			{
				Source:      runtimeBinPath,
				Destination: "/edge-runtime",
				Device:      "bind",
				Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
			},
			{
				Source:      esZipPath,
				Destination: "/bin.eszip",
				Device:      "bind",
				Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
			},
		},
		// TODO(dilyevsky): User/group mappings can not be specified without the NEWUSER flag (see above).
		//UIDMappings: []configs.IDMap{
		//	{
		//		ContainerID: 0,
		//		HostID:      1000,
		//		Size:        65536,
		//	},
		//},
		//GIDMappings: []configs.IDMap{
		//	{
		//		ContainerID: 0,
		//		HostID:      1000,
		//		Size:        65536,
		//	},
		//},
		Rlimits: []configs.Rlimit{
			{
				Type: unix.RLIMIT_NOFILE,
				Hard: 1024,
				Soft: 1024,
			},
		},
	}

	if _, err := os.Stat("/lib64"); err == nil {
		c.Mounts = append(c.Mounts, &configs.Mount{
			Source:      "/lib64",
			Destination: "/lib64",
			Device:      "bind",
			Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
		})
	}
	if _, err := os.Stat("/usr/lib"); err == nil {
		c.Mounts = append(c.Mounts, &configs.Mount{
			Source:      "/usr/lib",
			Destination: "/usr/lib",
			Device:      "bind",
			Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
		})
	}
	if _, err := os.Stat("/usr/lib64"); err == nil {
		c.Mounts = append(c.Mounts, &configs.Mount{
			Source:      "/usr/lib64",
			Destination: "/usr/lib64",
			Device:      "bind",
			Flags:       syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_REC,
		})
	}

	return c
}

func newNs(rid string) (netns.NsHandle, error) {
	// Need to lock OS thread bc netns is using thread-local data.
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return netns.None(), fmt.Errorf("failed to get current netns: %v", err)
	}
	defer netns.Set(origns)

	return netns.NewNamed(rid)
}

// Start requests the runtime to start the execution of the function.
func (r *runtime) Start(ctx context.Context, id string, esZipPath string) error {
	status, err := r.Status(ctx, id)
	if err == nil && status.State != edgefunc.StateStopped {
		return edgefunc.ErrAlreadyExists
	}

	h, err := newNs(id)
	if err != nil {
		return fmt.Errorf("failed to create netns: %v", err)
	}

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
	resolvedEsZipPath, err := filepath.EvalSymlinks(esZipPath)
	if err != nil {
		return fmt.Errorf("failed to resolve eszip symlink: %v", err)
	}

	cfg := config(id, rootFS, r.runtimeBinPath, resolvedEsZipPath)
	ctr, err := libcontainer.Create(r.stateDir, id, cfg)
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}

	args := []string{
		"/edge-runtime",
		"start",
		"--verbose",
		// TODO(dilyevsky): Cache is located at /root/.cache/deno/node_analysis_cache_v1 -
		// mount it from the host.
		"--disable-module-cache",
		"--main-service=/bin.eszip",
	}
	p := &libcontainer.Process{
		Args:            args,
		User:            "0:0",
		Cwd:             "/",
		NoNewPrivileges: ptr.To(true),

		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		LogLevel: "5", // logrus.DebugLevel index.

		Init: true,
	}

	log.Infof("Running edge-runtime container %s", id)

	if err := ctr.Run(p); err != nil {
		if err := ctr.Destroy(); err != nil {
			log.Errorf("failed to destroy container: %v", err)
		}
		return fmt.Errorf("failed to run container: %v", err)
	}

	log.Infof("Container %s started", id)

	return nil
}

// Stop requests the runtime to stop the execution of the function.
func (r *runtime) Stop(ctx context.Context, id string) error {
	ctr, err := libcontainer.Load(r.stateDir, id)
	if err != nil && err != libcontainer.ErrNotExist {
		return fmt.Errorf("failed to load container: %v", err)
	} else if err == libcontainer.ErrNotExist {
		return edgefunc.ErrNotFound
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
	if err != nil && err != libcontainer.ErrNotExist {
		return edgefunc.Status{}, fmt.Errorf("failed to load container: %v", err)
	} else if err == libcontainer.ErrNotExist {
		return edgefunc.Status{}, edgefunc.ErrNotFound
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
