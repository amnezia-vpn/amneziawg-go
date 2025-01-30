package multihoptun

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// This is a special implementation of `tun.Device` that allows to connect a
// `conn.Bind` from one WireGuard device to another's `tun.Device`. This way,
// we can create a multi-hop WireGuard device that can use the same private key
// and elude any MTU issues, since, for any single user packet, there is only
// ever a single read from the real tunnel device needed to send it to the
// entry hop.
//
// tun.Device.Write will push a buffer via writeRecv to be read by the recvfunc
// of conn.Bind, stripping IPv4/IPv6 + UDP headers in the process. When the
// packets have been transferred to the UDP receiver, writeDone will be used to
// return from tun.Device.Write. Conversely, conn.Bind.Send will push a buffer
// via readRecv to be read by tun.Device.Read, adding valid IPv4/IPv6 + UDP
// headers in the process.
//
// Implements tun.Device and can create instances of conn.Bind.
type MultihopTun struct {
	readRecv       chan packetBatch
	writeRecv      chan packetBatch
	isIpv4         bool
	localIp        []byte
	localPort      uint16
	remoteIp       []byte
	remotePort     uint16
	ipConnectionId uint16
	tunEvent       chan tun.Event
	mtu            int
	endpoint       conn.Endpoint
	closed         atomic.Bool
	shutdownChan   chan struct{}
}

type packetBatch struct {
	packet []byte
	size   int
	offset int
	// to be used to return the packet batch back to tun.Read and tun.Write
	completion chan packetBatch
}

func (pb *packetBatch) Size() int {
	return len(pb.packet)
}

func NewMultihopTun(local, remote netip.Addr, remotePort uint16, mtu int) MultihopTun {
	readRecv := make(chan packetBatch)
	writeRecv := make(chan packetBatch)
	endpoint, err := conn.NewStdNetBind().ParseEndpoint(netip.AddrPortFrom(remote, remotePort).String())
	if err != nil {
		panic("Failed to parse endpoint")
	}

	connectionId := uint16(rand.Uint32()>>16) | 1
	shutdownChan := make(chan struct{})

	return MultihopTun{
		readRecv,
		writeRecv,
		local.Is4(),
		local.AsSlice(),
		0,
		remote.AsSlice(),
		remotePort,
		connectionId,
		make(chan tun.Event),
		mtu,
		endpoint,
		atomic.Bool{},
		shutdownChan,
	}
}

func (st *MultihopTun) Binder() conn.Bind {
	socketShutdown := make(chan struct{})
	return &multihopBind{
		st,
		socketShutdown,
	}

}

// Events implements tun.Device.
func (st *MultihopTun) Events() <-chan tun.Event {
	return st.tunEvent
}

// File implements tun.Device.
func (*MultihopTun) File() *os.File {
	return nil
}

// MTU implements tun.Device.
func (st *MultihopTun) MTU() (int, error) {
	return st.mtu, nil
}

// Name implements tun.Device.
func (*MultihopTun) Name() (string, error) {
	return "stun", nil
}

// Write implements tun.Device.
func (st *MultihopTun) Write(packets [][]byte, offset int) (int, error) {
	for i, packet := range packets {
		completion := make(chan packetBatch)
		packetBatch := packetBatch{
			packet:     packet,
			offset:     offset,
			size:       len(packet),
			completion: completion,
		}

		select {
		case st.writeRecv <- packetBatch:
			break
		case <-st.shutdownChan:
			return i, io.EOF
		}

		packetBatch, ok := <-completion

		if !ok {
			return i, io.EOF
		}
	}

	return len(packets), nil
}

// Read implements tun.Device.
func (st *MultihopTun) Read(packet [][]byte, sizes []int, offset int) (n int, err error) {
	completion := make(chan packetBatch)
	packetBatch := packetBatch{
		packet:     packet[0],
		size:       0,
		offset:     offset,
		completion: completion,
	}

	select {
	case st.readRecv <- packetBatch:
		break
	case <-st.shutdownChan:
		return 0, io.EOF
	}

	var ok bool
	packetBatch, ok = <-completion

	if !ok {
		return 0, io.EOF
	}

	sizes[0] = packetBatch.size
	return 1, nil
}

func (st *MultihopTun) writePayload(target, payload []byte) (size int, err error) {
	headerSize := st.headerSize()
	if headerSize+len(payload) > len(target) {
		err = errors.New(fmt.Sprintf("target buffer is too small, need %d, got %d", headerSize+len(payload), len(target)))
		return
	}

	if st.isIpv4 {
		return st.writeV4Payload(target, payload)
	} else {
		return st.writeV6Payload(target, payload)
	}
}

func (st *MultihopTun) writeV4Payload(target, payload []byte) (size int, err error) {
	var ipv4 header.IPv4
	ipv4 = target

	size = st.headerSize() + len(payload)
	src := tcpip.AddrFrom4Slice(st.localIp)
	dst := tcpip.AddrFrom4Slice(st.remoteIp)
	fields := header.IPv4Fields{
		// TODO: Figure out the best DSCP value, ideally would be 0x88 for handshakes and 0x00 for rest.
		TOS:         0,
		TotalLength: uint16(size),
		ID:          st.ipConnectionId,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
		Checksum:    0,
	}
	ipv4.Encode(&fields)
	ipv4.SetChecksum(^ipv4.CalculateChecksum())
	st.writeUdpPayload(ipv4.Payload(), payload, src, dst)
	return
}

func (st *MultihopTun) writeV6Payload(target, payload []byte) (size int, err error) {

	var ipv6 header.IPv6
	ipv6 = target

	size = st.headerSize() + len(payload)
	src := tcpip.AddrFrom4Slice(st.localIp)
	dst := tcpip.AddrFrom4Slice(st.remoteIp)
	fields := header.IPv6Fields{
		TrafficClass:      0,
		PayloadLength:     uint16(len(payload)),
		FlowLabel:         uint32(st.ipConnectionId),
		TransportProtocol: header.UDPProtocolNumber,
		SrcAddr:           src,
		DstAddr:           dst,
		HopLimit:          64,
	}
	ipv6.Encode(&fields)

	st.writeUdpPayload(ipv6.Payload(), payload, src, dst)
	return
}

func (st *MultihopTun) writeUdpPayload(target header.UDP, payload []byte, src, dst tcpip.Address) {
	target.Encode(&header.UDPFields{
		SrcPort:  st.localPort,
		DstPort:  st.remotePort,
		Length:   uint16(len(payload) + header.UDPMinimumSize),
		Checksum: 0,
	})
	copy(target.Payload()[:], payload[:])

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	xsum := target.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(len(payload)+header.UDPMinimumSize)),
		checksum.Checksum(target, 0),
	))
	// As per RFC 768 page 2,
	//
	//   Checksum is the 16-bit one's complement of the one's complement sum of
	//   a pseudo header of information from the IP header, the UDP header, and
	//   the data, padded with zero octets at the end (if necessary) to make a
	//   multiple of two octets.
	//
	//	 The pseudo header conceptually prefixed to the UDP header contains the
	//   source address, the destination address, the protocol, and the UDP
	//   length. This information gives protection against misrouted datagrams.
	//   This checksum procedure is the same as is used in TCP.
	//
	//   If the computed checksum is zero, it is transmitted as all ones (the
	//   equivalent in one's complement arithmetic). An all zero transmitted
	//   checksum value means that the transmitter generated no checksum (for
	//   debugging or for higher level protocols that don't care).
	//
	// To avoid the zero value, we only calculate the one's complement of the
	// one's complement sum if the sum is not all ones.
	if xsum != math.MaxUint16 {
		xsum = ^xsum
	}
	target.SetChecksum(0)

}

func (st *MultihopTun) headerSize() int {
	udpPacketSize := header.UDPMinimumSize
	if st.isIpv4 {
		return header.IPv4MinimumSize + udpPacketSize
	} else {
		return header.IPv6MinimumSize + udpPacketSize
	}
}

// BatchSize implements conn.Bind.
func (*MultihopTun) BatchSize() int {
	return 128
}

// BatchSize implements conn.Bind.
func (*MultihopTun) Flush() error {
	return nil
}

// Close implements tun.Device
func (st *MultihopTun) Close() error {
	if !st.closed.Load() {
		st.closed.Store(true)
	}
	close(st.shutdownChan)
	return nil
}
