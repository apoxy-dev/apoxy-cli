package utils

import (
	"errors"
	"net"
)

// UnusedUDP4Port returns an unused UDP port.
func UnusedUDP4Port() (uint16, error) {
	for i := 0; i < 10; i++ {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		if err != nil {
			return 0, err
		}
		l, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return uint16(l.LocalAddr().(*net.UDPAddr).Port), nil
	}
	return 0, errors.New("could not find unused UDP port")
}
