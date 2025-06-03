//go:build linux

package fasttun_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/fasttun"
	"github.com/apoxy-dev/apoxy/pkg/utils/vm"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
)

func TestLinuxDeviceThroughput(t *testing.T) {
	child := vm.RunTestInVM(t, vm.WithPackages("iperf3"))
	if !child {
		return
	}

	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Is iperf3 installed?
	if _, err := exec.LookPath("iperf3"); err != nil {
		t.Skipf("skipping test: %v", err)
	}

	iperf3Major, iperf3Minor, err := iperf3Version()
	require.NoError(t, err)
	require.GreaterOrEqual(t, iperf3Major, 3)
	parallelSupport := iperf3Major > 3 || (iperf3Major == 3 && iperf3Minor >= 16)

	// Backup the host network namespace
	hostns, err := netns.Get()
	require.NoError(t, err)

	// Create network namespaces
	ns1, err := netns.NewNamed("fasttun-ns1")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, ns1.Close())
		require.NoError(t, netns.DeleteNamed("fasttun-ns1"))
	})

	ns2, err := netns.NewNamed("fasttun-ns2")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, ns2.Close())
		require.NoError(t, netns.DeleteNamed("fasttun-ns2"))
	})

	tun1 := fasttun.NewDevice("tun1", netstack.IPv6MinMTU)
	t.Cleanup(func() {
		require.NoError(t, tun1.Close())
	})

	// Create packet queues
	nPacketQueues := runtime.NumCPU()
	tun1Queues := make([]fasttun.PacketQueue, nPacketQueues)
	for i := 0; i < nPacketQueues; i++ {
		q, err := tun1.NewPacketQueue()
		require.NoError(t, err)
		tun1Queues[i] = q
	}

	err = configureTun(tun1.Name(), netip.MustParsePrefix("fd00::1/64"), hostns, ns1)
	require.NoError(t, err)

	tun2 := fasttun.NewDevice("tun2", netstack.IPv6MinMTU)
	t.Cleanup(func() {
		require.NoError(t, tun2.Close())
	})

	// Create packet queues
	tun2Queues := make([]fasttun.PacketQueue, nPacketQueues)
	for i := 0; i < nPacketQueues; i++ {
		q, err := tun2.NewPacketQueue()
		require.NoError(t, err)
		tun2Queues[i] = q
	}

	err = configureTun(tun2.Name(), netip.MustParsePrefix("fd00::2/64"), hostns, ns2)
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(t.Context())

	g.Go(func() error {
		<-ctx.Done()

		if err := tun1.Close(); err != nil {
			return fmt.Errorf("failed to close tun1: %w", err)
		}

		if err := tun2.Close(); err != nil {
			return fmt.Errorf("failed to close tun2: %w", err)
		}

		return nil
	})

	for i := 0; i < nPacketQueues; i++ {
		i := i
		g.Go(func() error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			return fasttun.Splice(ctx, tun1Queues[i], tun2Queues[i], tun1Queues[i].BatchSize(), netstack.IPv6MinMTU)
		})
	}

	g.Go(func() error {
		// Wait for the TUN devices to be ready
		time.Sleep(1 * time.Second)

		// Start iperf3 server in ns1
		server := exec.CommandContext(ctx, "ip", "netns", "exec", "fasttun-ns1",
			"iperf3", "-V", "-s")
		server.Stdout = os.Stdout
		server.Stderr = os.Stderr
		if err := server.Start(); err != nil {
			return fmt.Errorf("iperf3 server start failed: %w", err)
		}
		defer server.Process.Kill()

		// Give server time to start
		time.Sleep(1 * time.Second)

		// Run iperf3 client in ns2
		clientArgs := []string{"-V", "-C", "cubic", "-c", "fd00::1", "-t", "10"}
		if parallelSupport {
			clientArgs = append(clientArgs, "-P", strconv.Itoa(nPacketQueues))
		}

		cmdArgs := append([]string{"netns", "exec", "fasttun-ns2", "iperf3"}, clientArgs...)
		client := exec.CommandContext(ctx, "ip", cmdArgs...)
		client.Stdout = os.Stdout
		client.Stderr = os.Stderr
		if err := client.Run(); err != nil {
			return fmt.Errorf("iperf3 client failed: %w", err)
		}

		return context.Canceled // Signal completion.
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func configureTun(name string, addr netip.Prefix, hostns, ns netns.NsHandle) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get TUN device link: %w", err)
	}

	// Move the link to the target namespace
	if err := netlink.LinkSetNsFd(link, int(ns)); err != nil {
		return fmt.Errorf("failed to set TUN device namespace: %w", err)
	}

	// Jump to the target namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("failed to set target namespace: %w", err)
	}
	defer netns.Set(hostns)

	nlAddr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return fmt.Errorf("failed to parse TUN device address: %w", err)
	}

	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		return fmt.Errorf("failed to add address to TUN device: %w", err)
	}

	if err := netlink.LinkSetMTU(link, netstack.IPv6MinMTU); err != nil {
		return fmt.Errorf("failed to set TUN device MTU: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set TUN device up: %w", err)
	}

	return nil
}

func iperf3Version() (major, minor int, err error) {
	output, err := exec.Command("iperf3", "-v").Output()
	if err != nil {
		return 0, 0, fmt.Errorf("iperf3 not found or failed to run: %w", err)
	}

	var version string
	_, err = fmt.Sscanf(string(output), "iperf %s", &version)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse iperf3 version: %w", err)
	}

	n, err := fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to extract major.minor version: %w", err)
	}
	if n != 2 {
		return 0, 0, fmt.Errorf("unexpected version format")
	}

	return major, minor, nil
}
