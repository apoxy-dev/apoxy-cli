package net

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.zx2c4.com/wireguard/tun"
)

var _ tun.Device = (*PcapDevice)(nil)

type PcapDevice struct {
	dev tun.Device
	w   *pcapgo.Writer
}

func NewPcapDevice(dev tun.Device, pcapPath string) (*PcapDevice, error) {
	f, err := os.Create(pcapPath)
	if err != nil {
		return nil, err
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeIPv6); err != nil {
		return nil, err
	}

	return &PcapDevice{
		dev: dev,
		w:   w,
	}, nil
}

func (d *PcapDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if len(buf) <= offset {
			slog.Warn("PcapDevice.Write: skipping short buffer",
				slog.Int("len", len(buf)), slog.Int("offset", offset))
			continue
		}
		packetData := buf[offset:]
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}
		if err := d.w.WritePacket(ci, packetData); err != nil {
			return 0, fmt.Errorf("failed to write packet: %w", err)
		}
	}

	n, err := d.dev.Write(bufs, offset)
	if err != nil {
		return n, err
	}

	return n, nil
}

func (d *PcapDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	n, err = d.dev.Read(bufs, sizes, offset)
	if err != nil {
		return n, err
	}

	for i := 0; i < n; i++ {
		if len(bufs[i]) < offset+sizes[i] {
			slog.Warn("PcapDevice.Read: skipping short buffer",
				slog.Int("len", len(bufs[i])), slog.Int("offset", offset), slog.Int("size", sizes[i]))
			continue
		}
		packetData := bufs[i][offset : offset+sizes[i]]
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}
		if err := d.w.WritePacket(ci, packetData); err != nil {
			return 0, fmt.Errorf("failed to write packet: %w", err)
		}
	}

	return n, nil
}

func (d *PcapDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *PcapDevice) Close() error {
	return d.dev.Close()
}

func (d *PcapDevice) Events() <-chan tun.Event {
	return d.dev.Events()
}

func (d *PcapDevice) File() *os.File {
	return d.dev.File()
}

func (d *PcapDevice) MTU() (int, error) {
	return d.dev.MTU()
}

func (d *PcapDevice) Name() (string, error) {
	return d.dev.Name()
}
