//go:build linux

// Package runc implements container runtime based on OpenContainers
// libcontainer package.
package runc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	"github.com/opencontainers/runc/libcontainer/specconv"
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

// Exec implements edgefunc.Runtime.Exec.
func (r *runtime) Exec(ctx context.Context, id string, esZipPath string) error {
	status, err := r.ExecStatus(ctx, id)
	if err == nil && status.State != edgefunc.StateStopped {
		return edgefunc.ErrAlreadyExists
	}

	if err := r.net.Up(ctx, id); err != nil {
		return fmt.Errorf("failed to bring up network: %v", err)
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

// StopExec implements edgefunc.Runtime.StopExec.
func (r *runtime) StopExec(ctx context.Context, id string) error {
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

// DeleteExec implements edgefunc.Runtime.DeleteExec.
func (r *runtime) DeleteExec(ctx context.Context, id string) error {
	ctr, err := libcontainer.Load(r.stateDir, id)
	if err != nil && err != libcontainer.ErrNotExist {
		return fmt.Errorf("failed to load container: %v", err)
	} else if err == libcontainer.ErrNotExist {
		return edgefunc.ErrNotFound
	}
	if err := ctr.Destroy(); err != nil {
		return fmt.Errorf("failed to destroy container: %v", err)
	}
	if err := r.net.Down(ctx, id); err != nil {
		return fmt.Errorf("failed to bring down network: %v", err)
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

// ExecStatus implements edgefunc.Runtime.ExecStatus.
func (r *runtime) ExecStatus(ctx context.Context, id string) (edgefunc.Status, error) {
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

// ListExecs implements edgefunc.Runtime.ListExecs.
func (r *runtime) ListExecs(ctx context.Context) ([]edgefunc.Status, error) {
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
