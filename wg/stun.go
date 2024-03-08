package wg

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
)

const (
	stunTimeout = 5 * time.Second
)

func trySTUN(srcPort int, addrs ...string) (net.IP, []int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: srcPort})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP port: %w", err)
	}
	if err := c.SetDeadline(time.Now().Add(stunTimeout)); err != nil {
		return nil, nil, fmt.Errorf("failed to set STUN timeout: %w", err)
	}
	defer c.Close()

	log.Printf("Resolving STUN server %s\n", addrs[0])

	wg := sync.WaitGroup{}
	pCh := make(chan int)
	var mu sync.Mutex
	var extAddr net.IP
	for _, addr := range addrs {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()

			log.Printf("Resolving STUN server %s", server)

			addr, port, err := resolve(c, server)
			if err != nil {
				log.Printf("failed to resolve STUN server: %v", err)
				return
			}
			mu.Lock()
			if extAddr != nil && !extAddr.Equal(addr) {
				log.Printf("STUN server %s returned different IP address: %s", server, addr)
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

	log.Printf("STUN server %s returned IP address: %v\n", addr, xorAddr)

	return xorAddr.IP, xorAddr.Port, nil
}
