//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package fasttun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// Packet represents a network packet with virtio-net header and IP data.
type Packet struct {
	// Header buffer stores the virtio-net header
	headerBuf [virtioNetHdrLen]byte
	// Data buffer stores the IP packet
	dataBuf []byte
	// The full packet buffer is created on demand
	buffer []byte
}

// NewPacket creates a Packet from a raw buffer.
func NewPacket(buffer []byte) *Packet {
	return &Packet{
		headerBuf: [virtioNetHdrLen]byte{},
		dataBuf:   buffer,
	}
}

// Header returns the virtio-net header portion of the packet.
func (p *Packet) Header() []byte {
	return p.headerBuf[:]
}

// Data returns the IP packet portion, without the virtio-net header.
func (p *Packet) Data() []byte {
	return p.dataBuf
}

// Full returns the entire buffer (header + data).
func (p *Packet) Full() []byte {
	if p.buffer == nil {
		// Concatenate header and data buffers on demand
		p.buffer = append(p.headerBuf[:], p.dataBuf...)
	}
	return p.buffer
}

// VirtioNetHdr parses and returns the virtio-net header.
func (p *Packet) VirtioNetHdr() virtioNetHdr {
	var hdr virtioNetHdr
	_ = hdr.decode(p.Header())
	return hdr
}

// SetVirtioNetHdr updates the virtio-net header in the packet.
func (p *Packet) SetVirtioNetHdr(hdr virtioNetHdr) error {
	return hdr.encode(p.Header())
}

// PacketBatch represents a collection of packets for batch processing.
type PacketBatch struct {
	packets []*Packet
}

// NewPacketBatch creates a batch from raw buffers.
func NewPacketBatch(buffers [][]byte) *PacketBatch {
	packets := make([]*Packet, len(buffers))
	for i, buf := range buffers {
		packets[i] = NewPacket(buf)
	}
	return &PacketBatch{packets: packets}
}

// Get returns the packet at the specified index.
func (pb *PacketBatch) Get(index int) *Packet {
	return pb.packets[index]
}

// Len returns the number of packets in the batch.
func (pb *PacketBatch) Len() int {
	return len(pb.packets)
}

const tcpFlagsOffset = 13

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)

// virtioNetHdr is defined in the kernel in include/uapi/linux/virtio_net.h. The
// kernel symbol is virtio_net_hdr.
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

const (
	// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
	// shape of the C ABI for its kernel counterpart -- sizeof(virtio_net_hdr).
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

// tcpFlowKey represents the key for a TCP flow.
type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	rxAck            uint32 // varying ack values should not be coalesced. Treat them as separate flows.
	isV6             bool
}

// tcpGROTable holds flow and coalescing information for the purposes of TCP GRO.
type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]tcpGROItem, conn.IdealBatchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, conn.IdealBatchSize)
	}
	return t
}

func newTCPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset int) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	key.isV6 = addrSize == 16
	return key
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	t.insert(pkt, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (t *tcpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		sentSeq:   binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:    pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items, _ := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type tcpGROItem struct {
	key       tcpFlowKey
	sentSeq   uint32 // the sequence number
	bufsIndex uint16 // the index into the original bufs slice
	numMerged uint16 // the number of packets merged into this item
	gsoSize   uint16 // payload size
	iphLen    uint8  // ip header len
	tcphLen   uint8  // tcp header len
	pshSet    bool   // psh flag is set
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, k)
	}
}

// udpFlowKey represents the key for a UDP flow.
type udpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	isV6             bool
}

// udpGROTable holds flow and coalescing information for the purposes of UDP GRO.
type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem
	itemsPool   [][]udpGROItem
}

func newUDPGROTable() *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]udpGROItem, conn.IdealBatchSize),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, conn.IdealBatchSize)
	}
	return u
}

func newUDPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset int) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (u *udpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	u.insert(pkt, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex, false)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (u *udpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	item := udpGROItem{
		key:              key,
		bufsIndex:        uint16(bufsIndex),
		gsoSize:          uint16(len(pkt[udphOffset+udphLen:])),
		iphLen:           uint8(udphOffset),
		cSumKnownInvalid: cSumKnownInvalid,
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items, _ := u.itemsByFlow[item.key]
	items[i] = item
}

// udpGROItem represents bookkeeping data for a UDP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type udpGROItem struct {
	key              udpFlowKey
	bufsIndex        uint16 // the index into the original bufs slice
	numMerged        uint16 // the number of packets merged into this item
	gsoSize          uint16 // payload size
	iphLen           uint8  // ip header len
	cSumKnownInvalid bool   // UDP header checksum validity; a false value DOES NOT imply valid, just unknown.
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, k)
	}
}

// canCoalesce represents the outcome of checking if two TCP packets are
// candidates for coalescing.
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

// ipHeadersCanCoalesce returns true if the IP headers found in pktA and pktB
// meet all requirements to be merged as part of a GRO operation, otherwise it
// returns false.
func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	if pktA[0]>>4 == 6 {
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			// cannot coalesce with unequal Traffic class values
			return false
		}
		if pktA[7] != pktB[7] {
			// cannot coalesce with unequal Hop limit values
			return false
		}
	} else {
		if pktA[1] != pktB[1] {
			// cannot coalesce with unequal ToS values
			return false
		}
		if pktA[6]>>5 != pktB[6]>>5 {
			// cannot coalesce with unequal DF or reserved bits. MF is checked
			// further up the stack.
			return false
		}
		if pktA[8] != pktB[8] {
			// cannot coalesce with unequal TTL values
			return false
		}
	}
	return true
}

// udpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. iphLen and gsoSize describe pkt. bufs is the vector of
// packets involved in the current GRO evaluation. bufsOffset is the offset at
// which packet data begins within bufs.
func udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16, item udpGROItem, batch *PacketBatch) canCoalesce {
	pktTarget := batch.Get(int(item.bufsIndex)).Data()
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	if len(pktTarget[iphLen+udphLen:])%int(item.gsoSize) != 0 {
		// A smaller than gsoSize packet has been appended previously.
		// Nothing can come after a smaller packet on the end.
		return coalesceUnavailable
	}
	if gsoSize > item.gsoSize {
		// We cannot have a larger packet following a smaller one.
		return coalesceUnavailable
	}
	return coalesceAppend
}

// tcpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. This function makes considerations that match the kernel's
// GRO self tests, which can be found in tools/testing/selftests/net/gro.c.
func tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8, seq uint32, pshSet bool, gsoSize uint16, item tcpGROItem, batch *PacketBatch) canCoalesce {
	pktTarget := batch.Get(int(item.bufsIndex)).Data()
	if tcphLen != item.tcphLen {
		// cannot coalesce with unequal tcp options len
		return coalesceUnavailable
	}
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen], pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			// cannot coalesce with unequal tcp options
			return coalesceUnavailable
		}
	}
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	// seq adjacency
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize
	if seq == item.sentSeq+uint32(lhsLen) { // pkt aligns following item from a seq num perspective
		if item.pshSet {
			// We cannot append to a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			// A smaller than gsoSize packet has been appended previously.
			// Nothing can come after a smaller packet on the end.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq { // pkt aligns in front of item from a seq num perspective
		if pshSet {
			// We cannot prepend with a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			// There's at least one previous merge, and we're larger than all
			// previous. This would put multiple smaller packets on the end.
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

func checksumValid(pkt []byte, iphLen, proto uint8, isV6 bool) bool {
	srcAddrAt := ipv4SrcAddrOffset
	addrSize := 4
	if isV6 {
		srcAddrAt = ipv6SrcAddrOffset
		addrSize = 16
	}
	lenForPseudo := uint16(len(pkt) - int(iphLen))
	cSum := pseudoHeaderChecksumNoFold(proto, pkt[srcAddrAt:srcAddrAt+addrSize], pkt[srcAddrAt+addrSize:srcAddrAt+addrSize*2], lenForPseudo)
	return ^checksum(pkt[iphLen:], cSum) == 0
}

// coalesceResult represents the result of attempting to coalesce two TCP
// packets.
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidCSum
	coalescePktInvalidCSum
	coalesceSuccess
)

// coalesceUDPPackets attempts to coalesce pkt with the packet described by
// item, and returns the outcome.
func coalesceUDPPackets(pkt []byte, item *udpGROItem, batch *PacketBatch, isV6 bool) coalesceResult {
	pktHead := batch.Get(int(item.bufsIndex)).Data() // the packet that will end up at the front
	headersLen := item.iphLen + udphLen
	coalescedLen := len(pktHead) + len(pkt) - int(headersLen)

	packet := batch.Get(int(item.bufsIndex))
	if cap(packet.buffer)-virtioNetHdrLen < coalescedLen {
		// We don't want to allocate a new underlying array if capacity is
		// too small.
		return coalesceInsufficientCap
	}
	if item.numMerged == 0 {
		if item.cSumKnownInvalid || !checksumValid(packet.Data(), item.iphLen, unix.IPPROTO_UDP, isV6) {
			return coalesceItemInvalidCSum
		}
	}
	if !checksumValid(pkt, item.iphLen, unix.IPPROTO_UDP, isV6) {
		return coalescePktInvalidCSum
	}
	extendBy := len(pkt) - int(headersLen)
	// Extend the buffer
	newBuffer := append(packet.buffer[:virtioNetHdrLen+len(pktHead)], make([]byte, extendBy)...)
	packet.buffer = newBuffer
	// Copy the payload
	copy(packet.buffer[virtioNetHdrLen+len(pktHead):], pkt[headersLen:])

	item.numMerged++
	return coalesceSuccess
}

// coalesceTCPPackets attempts to coalesce pkt with the packet described by
// item, and returns the outcome. This function may swap bufs elements in the
// event of a prepend as item's bufs index is already being tracked for writing
// to a Device.
func coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int, gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, batch *PacketBatch, isV6 bool) coalesceResult {
	headersLen := item.iphLen + item.tcphLen
	targetPacket := batch.Get(int(item.bufsIndex))
	pktHeadData := targetPacket.Data()
	coalescedLen := len(pktHeadData) + len(pkt) - int(headersLen)

	// Copy data
	if mode == coalescePrepend {
		srcPacket := batch.Get(pktBuffsIndex)
		// For prepend, we're using the incoming packet as the head
		if cap(srcPacket.buffer)-virtioNetHdrLen < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !checksumValid(targetPacket.Data(), item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		item.sentSeq = seq
		extendBy := coalescedLen - len(pkt)

		// Create space in the source packet's buffer
		newBuffer := append(srcPacket.buffer[:virtioNetHdrLen+len(pkt)], make([]byte, extendBy)...)
		srcPacket.buffer = newBuffer

		// Copy the payload from the target packet to the end of the source packet
		copy(srcPacket.buffer[virtioNetHdrLen+len(pkt):], targetPacket.Data()[int(headersLen):])

		// Swap the packet references in the batch
		batch.packets[int(item.bufsIndex)], batch.packets[pktBuffsIndex] = batch.packets[pktBuffsIndex], batch.packets[int(item.bufsIndex)]
	} else {
		// For append, we're using the existing item as the head
		if cap(targetPacket.buffer)-virtioNetHdrLen < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !checksumValid(targetPacket.Data(), item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		if pshSet {
			// We are appending a segment with PSH set.
			item.pshSet = pshSet
			targetPacket.Data()[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		extendBy := len(pkt) - int(headersLen)
		// Extend the buffer
		newBuffer := append(targetPacket.buffer[:virtioNetHdrLen+len(pktHeadData)], make([]byte, extendBy)...)
		targetPacket.buffer = newBuffer
		// Copy the payload
		copy(targetPacket.buffer[virtioNetHdrLen+len(pktHeadData):], pkt[headersLen:])
	}

	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}

	item.numMerged++
	return coalesceSuccess
}

const (
	ipv4FlagMoreFragments uint8 = 0x20
)

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
	maxUint16         = 1<<16 - 1
)

type groResult int

const (
	groResultNoop groResult = iota
	groResultTableInsert
	groResultCoalesced
)

// tcpGRO evaluates the TCP packet at pktI in bufs for coalescing with
// existing packets tracked in table. It returns a groResultNoop when no
// action was taken, groResultTableInsert when the evaluated packet was
// inserted into table, and groResultCoalesced when the evaluated packet was
// coalesced with another packet in table.
func tcpGRO(batch *PacketBatch, pktI int, table *tcpGROTable, isV6 bool) groResult {
	packet := batch.Get(pktI)
	pkt := packet.Data()
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	if len(pkt) < iphLen+tcphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	// not a candidate if any non-ACK flags (except PSH+ACK) are set
	if tcpFlags != tcpFlagACK {
		if pkt[iphLen+tcpFlagsOffset] != tcpFlagACK|tcpFlagPSH {
			return groResultNoop
		}
		pshSet = true
	}
	gsoSize := uint16(len(pkt) - tcphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	for i := len(items) - 1; i >= 0; i-- {
		// In the best case of packets arriving in order iterating in reverse is
		// more efficient if there are multiple items for a given flow. This
		// also enables a natural table.deleteAt() in the
		// coalesceItemInvalidCSum case without the need for index tracking.
		// This algorithm makes a best effort to coalesce in the event of
		// unordered packets, where pkt may land anywhere in items from a
		// sequence number perspective, however once an item is inserted into
		// the table it is never compared across other items later.
		item := items[i]
		can := tcpPacketsCanCoalesce(pkt, uint8(iphLen), uint8(tcphLen), seq, pshSet, gsoSize, item, batch)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(can, pkt, pktI, gsoSize, seq, pshSet, &item, batch, isV6)
			switch result {
			case coalesceSuccess:
				table.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidCSum:
				// delete the item with an invalid csum
				table.deleteAt(item.key, i)
			case coalescePktInvalidCSum:
				// no point in inserting an item that we can't coalesce
				return groResultNoop
			default:
			}
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	return groResultTableInsert
}

// applyTCPCoalesceAccounting updates bufs to account for coalescing based on the
// metadata found in table.
func applyTCPCoalesceAccounting(batch *PacketBatch, table *tcpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + item.tcphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 16,
				}
				packet := batch.Get(int(item.bufsIndex))
				pkt := packet.Data()

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					iphCSum := ^checksum(pkt[:item.iphLen], 0)            // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)         // set IPv4 header checksum field
				}
				err := packet.SetVirtioNetHdr(hdr)
				if err != nil {
					return err
				}

				// Calculate the pseudo header checksum and place it at the TCP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the tcp header and payload checksum.
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddr := pkt[addrOffset : addrOffset+addrLen]
				dstAddr := pkt[addrOffset+addrLen : addrOffset+addrLen*2]
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))
			} else {
				packet := batch.Get(int(item.bufsIndex))
				hdr := virtioNetHdr{}
				err := packet.SetVirtioNetHdr(hdr)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// applyUDPCoalesceAccounting updates bufs to account for coalescing based on the
// metadata found in table.
func applyUDPCoalesceAccounting(batch *PacketBatch, table *udpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + udphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 6,
				}
				packet := batch.Get(int(item.bufsIndex))
				pkt := packet.Data()

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					iphCSum := ^checksum(pkt[:item.iphLen], 0)            // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)         // set IPv4 header checksum field
				}
				err := packet.SetVirtioNetHdr(hdr)
				if err != nil {
					return err
				}

				// Recalculate the UDP len field value
				binary.BigEndian.PutUint16(pkt[item.iphLen+4:], uint16(len(pkt[item.iphLen:])))

				// Calculate the pseudo header checksum and place it at the UDP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the udp header and payload checksum.
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddr := pkt[addrOffset : addrOffset+addrLen]
				dstAddr := pkt[addrOffset+addrLen : addrOffset+addrLen*2]
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))
			} else {
				packet := batch.Get(int(item.bufsIndex))
				hdr := virtioNetHdr{}
				err := packet.SetVirtioNetHdr(hdr)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type groCandidateType uint8

const (
	notGROCandidate groCandidateType = iota
	tcp4GROCandidate
	tcp6GROCandidate
	udp4GROCandidate
	udp6GROCandidate
)

func packetIsGROCandidate(b []byte, canUDPGRO bool) groCandidateType {
	if len(b) < 28 {
		return notGROCandidate
	}
	if b[0]>>4 == 4 {
		if b[0]&0x0F != 5 {
			// IPv4 packets w/IP options do not coalesce
			return notGROCandidate
		}
		if b[9] == unix.IPPROTO_TCP && len(b) >= 40 {
			return tcp4GROCandidate
		}
		if b[9] == unix.IPPROTO_UDP && canUDPGRO {
			return udp4GROCandidate
		}
	} else if b[0]>>4 == 6 {
		if b[6] == unix.IPPROTO_TCP && len(b) >= 60 {
			return tcp6GROCandidate
		}
		if b[6] == unix.IPPROTO_UDP && len(b) >= 48 && canUDPGRO {
			return udp6GROCandidate
		}
	}
	return notGROCandidate
}

const (
	udphLen = 8
)

// udpGRO evaluates the UDP packet at pktI in bufs for coalescing with
// existing packets tracked in table. It returns a groResultNoop when no
// action was taken, groResultTableInsert when the evaluated packet was
// inserted into table, and groResultCoalesced when the evaluated packet was
// coalesced with another packet in table.
func udpGRO(batch *PacketBatch, pktI int, table *udpGROTable, isV6 bool) groResult {
	packet := batch.Get(pktI)
	pkt := packet.Data()
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	if len(pkt) < iphLen+udphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	gsoSize := uint16(len(pkt) - udphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	// With UDP we only check the last item, otherwise we could reorder packets
	// for a given flow. We must also always insert a new item, or successfully
	// coalesce with an existing item, for the same reason.
	item := items[len(items)-1]
	can := udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, item, batch)
	var pktCSumKnownInvalid bool
	if can == coalesceAppend {
		result := coalesceUDPPackets(pkt, &item, batch, isV6)
		switch result {
		case coalesceSuccess:
			table.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidCSum:
			// If the existing item has an invalid csum we take no action. A new
			// item will be stored after it, and the existing item will never be
			// revisited as part of future coalescing candidacy checks.
		case coalescePktInvalidCSum:
			// We must insert a new item, but we also mark it as invalid csum
			// to prevent a repeat checksum validation.
			pktCSumKnownInvalid = true
		default:
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI, pktCSumKnownInvalid)
	return groResultTableInsert
}

// handleGRO evaluates packets for GRO, and writes the indices of the resulting
// packets into toWrite. toWrite, tcpTable, and udpTable should initially be
// empty (but non-nil), and are passed in to save allocs as the caller may reset
// and recycle them across vectors of packets. canUDPGRO indicates if UDP GRO is
// supported.
func handleGRO(batch *PacketBatch, tcpTable *tcpGROTable, udpTable *udpGROTable, canUDPGRO bool, toWrite *[]int) error {
	for i := 0; i < batch.Len(); i++ {
		packet := batch.Get(i)
		var result groResult
		switch packetIsGROCandidate(packet.Data(), canUDPGRO) {
		case tcp4GROCandidate:
			result = tcpGRO(batch, i, tcpTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(batch, i, tcpTable, true)
		case udp4GROCandidate:
			result = udpGRO(batch, i, udpTable, false)
		case udp6GROCandidate:
			result = udpGRO(batch, i, udpTable, true)
		}
		switch result {
		case groResultNoop:
			hdr := packet.VirtioNetHdr()
			err := packet.SetVirtioNetHdr(hdr)
			if err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(batch, tcpTable)
	errUDP := applyUDPCoalesceAccounting(batch, udpTable)
	return errors.Join(errTCP, errUDP)
}

// gsoSplit splits packets from in into outBuffs, writing the size of each
// element into sizes. It returns the number of buffers populated, and/or an
// error.
func gsoSplit(in []byte, hdr virtioNetHdr, outBuffs [][]byte, sizes []int, isV6 bool) (int, error) {
	iphLen := int(hdr.csumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if !isV6 {
		in[10], in[11] = 0, 0 // clear ipv4 header checksum
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	in[transportCsumAt], in[transportCsumAt+1] = 0, 0 // clear tcp/udp checksum
	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		firstTCPSeqNum = binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}
	nextSegmentDataAt := int(hdr.hdrLen)
	i := 0
	for ; nextSegmentDataAt < len(in); i++ {
		if i == len(outBuffs) {
			return i - 1, errors.New("too many segments")
		}
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen
		sizes[i] = totalLen
		packet := NewPacket(outBuffs[i])
		out := packet.Data()

		copy(out, in[:iphLen])
		if !isV6 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		// copy transport header
		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])

		if protocol == unix.IPPROTO_TCP {
			// set TCP seq and adjust TCP flags
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(in) {
				// FIN and PSH should only be set on last segment
				clearFlags := tcpFlagFIN | tcpFlagPSH
				out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			// set UDP header len
			binary.BigEndian.PutUint16(out[hdr.csumStart+4:], uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		// payload
		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		// transport checksum
		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSumNoFold := pseudoHeaderChecksumNoFold(protocol, in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], lenForPseudo)
		transportCSum := ^checksum(out[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], transportCSum)

		nextSegmentDataAt += int(hdr.gsoSize)
	}
	return i, nil
}

func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := cSumStart + cSumOffset
	// The initial value at the checksum offset should be summed with the
	// checksum we compute. This is typically the pseudo-header checksum.
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	in[cSumAt], in[cSumAt+1] = 0, 0
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum(in[cSumStart:], uint64(initial)))
	return nil
}

// handleVirtioRead splits in into bufs, leaving offset bytes at the front of
// each buffer. It mutates sizes to reflect the size of each element of bufs,
// and returns the number of packets read.
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int) (int, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// This means CHECKSUM_PARTIAL in skb context. We are responsible
			// for computing the checksum starting at hdr.csumStart and placing
			// at hdr.csumOffset.
			err = gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset)
			if err != nil {
				return 0, err
			}
		}
		packet := NewPacket(bufs[0])
		if len(in) > len(packet.Data()) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(packet.Data()))
		}
		n := copy(packet.Data(), in)
		sizes[0] = n
		return 1, nil
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}

	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	return gsoSplit(in, hdr, bufs, sizes, ipVersion == 6)
}
