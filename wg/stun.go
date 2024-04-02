package wg

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
)

const (
	stunTimeout = 5 * time.Second
)

// TrySTUN tries to resolve the external IP address and port of the host
// by sending a STUN request to the specified STUN servers.
func TrySTUN(srcPort int, addrs ...string) (net.IP, []int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: srcPort})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP port: %w", err)
	}
	if err := c.SetDeadline(time.Now().Add(stunTimeout)); err != nil {
		return nil, nil, fmt.Errorf("failed to set STUN timeout: %w", err)
	}
	defer c.Close()

	slog.Debug("Resolving STUN server", "addrs", addrs)

	wg := sync.WaitGroup{}
	pCh := make(chan int)
	var mu sync.Mutex
	var extAddr net.IP
	for _, addr := range addrs {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()

			slog.Debug("Resolving STUN server", "addr", server)

			addr, port, err := resolve(c, server)
			if err != nil {
				slog.Error("failed to resolve STUN server", "addr", server, "err", err)
				return
			}
			mu.Lock()
			if extAddr != nil && !extAddr.Equal(addr) {
				slog.Error("STUN server returned different external address", "addr", server, "extAddr", extAddr, "newAddr", addr)
				mu.Unlock()
				return
			}
			extAddr = addr
			mu.Unlock()

			pCh <- port
		}(addr)
	}
	go func() {
		wg.Wait()
		close(pCh)
	}()

	var ports []int
	for p := range pCh {
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil, nil, fmt.Errorf("failed to resolve any STUN server")
	}

	return extAddr, ports, nil
}

func resolve(conn *net.UDPConn, addr string) (net.IP, int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve STUN server address: %w", err)
	}

	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err = conn.WriteToUDP(m.Raw, uAddr); err != nil {
		return nil, 0, fmt.Errorf("failed to send STUN request to server: %w", err)
	}

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read message from STUN server: %w", err)
	}

	buf = buf[:n]
	if !stun.IsMessage(buf) {
		return nil, 0, fmt.Errorf("received invalid STUN message from server")
	}

	resp := &stun.Message{Raw: buf}
	if err := resp.Decode(); err != nil {
		return nil, 0, fmt.Errorf("failed to decode STUN server message: %w", err)
	}
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(resp); err != nil {
		return nil, 0, fmt.Errorf("failed to get XOR-MAPPED-ADDRESS from STUN server message: %w", err)
	}

	slog.Debug("STUN server returned IP address", "addr", addr, "ip", xorAddr.IP, "port", xorAddr.Port)

	return xorAddr.IP, xorAddr.Port, nil
}
