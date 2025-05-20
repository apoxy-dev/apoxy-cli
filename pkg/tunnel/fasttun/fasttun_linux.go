//go:build linux

package fasttun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ Device = (*LinuxDevice)(nil)

type LinuxDevice struct {
	name              string
	mtu               int
	packetQueuesMu    sync.Mutex
	packetQueues      []*LinuxPacketQueue
	configureLinkOnce sync.Once
	groHistogram      *hdrhistogram.Histogram
}

// NewDevice creates a new Linux TUN device with the given name and MTU.
// Initialization of the device is deferred until the first packet queue is created.
func NewDevice(name string, mtu int) *LinuxDevice {
	return &LinuxDevice{
		name:         name,
		mtu:          mtu,
		groHistogram: hdrhistogram.New(1, 1000000, 3), // 1 microsecond to 1 second with 3 sigfig precision
	}
}

func (d *LinuxDevice) Close() error {
	d.packetQueuesMu.Lock()
	defer d.packetQueuesMu.Unlock()

	// Print histogram data
	fmt.Printf("GRO processing time histogram (microseconds):\n")
	fmt.Printf("Min: %d, Max: %d, Mean: %.2f, StdDev: %.2f\n",
		d.groHistogram.Min(), d.groHistogram.Max(), d.groHistogram.Mean(), d.groHistogram.StdDev())
	fmt.Printf("50%%: %d, 90%%: %d, 99%%: %d, 99.9%%: %d\n",
		d.groHistogram.ValueAtQuantile(50), d.groHistogram.ValueAtQuantile(90),
		d.groHistogram.ValueAtQuantile(99), d.groHistogram.ValueAtQuantile(99.9))

	var closeErr error
	for _, q := range d.packetQueues {
		if err := q.Close(); err != nil && closeErr == nil {
			closeErr = err // capture the first error
		}
	}
	d.packetQueues = nil

	if closeErr != nil {
		return fmt.Errorf("failed to close packet queues: %w", closeErr)
	}

	return nil
}

func (d *LinuxDevice) Name() string {
	return d.name
}

func (d *LinuxDevice) MTU() (int, error) {
	return d.mtu, nil
}

// NewPacketQueue creates a new packet queue for the device.
func (d *LinuxDevice) NewPacketQueue() (PacketQueue, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(d.name)
	if err != nil {
		return nil, err
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	tunFile := os.NewFile(uintptr(fd), "/dev/net/tun")

	q := &LinuxPacketQueue{
		tunFile:      tunFile,
		groHistogram: d.groHistogram,
		tcpGROTable:  newTCPGROTable(),
		udpGROTable:  newUDPGROTable(),
	}

	// Store a reference to the packet queue.
	d.packetQueuesMu.Lock()
	d.packetQueues = append(d.packetQueues, q)
	d.packetQueuesMu.Unlock()

	d.configureLinkOnce.Do(func() {
		link, err := netlink.LinkByName(d.name)
		if err != nil {
			err = fmt.Errorf("failed to get link by name: %w", err)
			return
		}

		if err := netlink.LinkSetMTU(link, d.mtu); err != nil {
			err = fmt.Errorf("failed to set MTU: %w", err)
			return
		}

		if err := netlink.LinkSetUp(link); err != nil {
			err = fmt.Errorf("failed to set link up: %w", err)
			return
		}
	})
	if err != nil {
		_ = q.Close()
		return nil, fmt.Errorf("failed to configure link: %w", err)
	}

	return q, nil
}

type LinuxPacketQueue struct {
	tunFile *os.File

	groHistogram *hdrhistogram.Histogram

	writeOpMu   sync.Mutex
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

func (q *LinuxPacketQueue) Close() error {
	return q.tunFile.Close()
}

func (q *LinuxPacketQueue) BatchSize() int {
	return 64
}

func (q *LinuxPacketQueue) Read(pkts [][]byte, sizes []int) (int, error) {
	fd := int(q.tunFile.Fd())
	timeout := 50 * time.Millisecond

	pollFds := []unix.PollFd{
		{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		},
	}

	n := 0
	for i := 0; i < len(pkts); i++ {
		if i == 0 {
			// Wait for initial packet or timeout
			nReady, err := pollWithRetry(pollFds, int(timeout.Milliseconds()))
			if err != nil {
				return 0, fmt.Errorf("poll error: %w", err)
			}
			if nReady == 0 {
				return 0, nil // timeout, no packets available
			}
		} else {
			// Check if more data is immediately ready
			pollFds[0].Events = unix.POLLIN
			pollFds[0].Revents = 0
			nReady, err := pollWithRetry(pollFds, 0)
			if err != nil {
				return n, fmt.Errorf("poll error during batching: %w", err)
			}
			if nReady == 0 {
				break // no more packets ready
			}
		}

		buf := pkts[i]
		nRead, err := q.tunFile.Read(buf)
		if err != nil {
			if n == 0 {
				return 0, err
			}
			return n, nil // return packets read so far
		}
		sizes[i] = nRead
		n++
	}

	return n, nil
}

func (q *LinuxPacketQueue) Write(pkts [][]byte) (int, error) {
	// New packets batch considered for GRO.
	batch := NewPacketBatch(pkts)

	q.writeOpMu.Lock()
	defer func() {
		q.tcpGROTable.reset()
		q.udpGROTable.reset()
		q.writeOpMu.Unlock()
	}()

	var (
		toWrite []int
		written int
		errs    error
	)

	// Record time of handleGRO
	startTime := time.Now()
	if err := handleGRO(batch, q.tcpGROTable, q.udpGROTable, true, &toWrite); err != nil {
		return 0, err
	}
	elapsed := time.Since(startTime)
	// Record in histogram in microseconds
	_ = q.groHistogram.RecordValue(elapsed.Microseconds())

	for _, idx := range toWrite {
		pkt := batch.Get(idx)
		_, err := q.tunFile.Write(pkt.Full())
		if errors.Is(err, unix.EBADFD) {
			return written, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			written++
		}
	}

	return written, errs
}

func pollWithRetry(pollFds []unix.PollFd, timeout int) (int, error) {
	for {
		n, err := unix.Poll(pollFds, timeout)
		if err == unix.EINTR {
			continue // retry on EINTR
		}
		return n, err
	}
}
