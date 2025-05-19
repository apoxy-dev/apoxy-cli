// Package fasttun implements a high-performance interface to Linux TUN devices
// with support for multi-queue and batched packet I/O.
package fasttun

import "io"

// Device represents a virtual TUN network interface.
// It provides methods to query device properties and create packet queues
// for reading and writing packets concurrently.
type Device interface {
	io.Closer

	// Name returns the name of the TUN device (e.g., "tun0").
	Name() string

	// MTU returns the device's Maximum Transmission Unit.
	MTU() (int, error)

	// NewPacketQueue creates a new packet queue for the device.
	// Each queue is associated with a file descriptor and can be used
	// concurrently with others.
	NewPacketQueue() (PacketQueue, error)
}

// PacketQueue represents a single queue for sending and receiving packets
// from a TUN device. It supports batch I/O for efficient packet processing.
type PacketQueue interface {
	io.Closer

	// BatchSize returns the recommended number of packets to process in one batch.
	// This is useful for optimizing I/O performance.
	BatchSize() int

	// Read reads packets into the provided buffer slices `pkts` and stores
	// the size of each packet in `sizes`.
	//
	// It returns the number of packets successfully read and an error, if any.
	// On timeout or no available packets, it may return (0, nil).
	Read(pkts [][]byte, sizes []int) (n int, err error)

	// Write writes the given packets to the TUN device.
	// It returns the number of packets successfully written and an error, if any.
	Write(pkts [][]byte) (int, error)
}
