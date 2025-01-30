package multihoptun

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestMultihopTunBind(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	virtualIp := netip.AddrFrom4([4]byte{192, 168, 1, 11})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)

	_ = device.NewDevice(&st, st.Binder(), device.NewLogger(device.LogLevelSilent, ""))
}

func TestMultihopTunTrafficV4(t *testing.T) {

	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	virtualTun, virtualNet, _ := netstack.CreateNetTUN([]netip.Addr{virtualIp}, []netip.Addr{}, 1280)

	// Pipe reads from virtualTun into multihop tun
	go func() {
		buf := make([][]byte, 1600)
		sizes := make([]int, 1)
		var err error
		for err == nil {
			_, err = virtualTun.Read(buf, sizes, 0)
			_, err = st.Write(buf[:sizes[0]], 0)
		}

	}()

	// Pipe reads from multihop tun into virtualTun
	go func() {
		buf := make([][]byte, 1600)
		sizes := make([]int, 1)
		var err error
		for err == nil {
			_, err = st.Read(buf, sizes, 0)
			_, err = virtualTun.Write(buf[:sizes[0]], 0)
		}
	}()

	recvFunc, _, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open port for multihop tun: %s", err)
	}

	payload := [][]byte{{1, 2, 3, 4}}
	readyChan := make(chan struct{})
	// Listen on the virtual tunnel
	go func() {
		conn, err := virtualNet.ListenUDPAddrPort(netip.AddrPortFrom(virtualIp, remotePort))
		if err != nil {
			panic(err)
		}
		readyChan <- struct{}{}
		buff := make([]byte, 4)
		n, addr, _ := conn.ReadFrom(buff)
		if n == 0 {
			fmt.Println("Did not receive anything")
		}

		conn.WriteTo(buff, addr)
	}()
	_, _ = <-readyChan

	err = stBind.Send(payload, nil)
	if err != nil {
		t.Fatalf("Failed ot send traffic to multihop tun: %s", err)
	}

	recvBuf := make([][]byte, 1600)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	_, err = recvFunc[0](recvBuf, sizes, eps)
	packetSize := sizes[0]
	if err != nil {
		t.Fatalf("Failed to receive traffic from recvFunc - %s", err)
	}
	if packetSize != len(payload) {
		t.Fatalf("Expected to recieve %d bytes, instead received %d", len(payload), packetSize)
	}

	for idx := range payload {
		if payload[0][idx] != recvBuf[0][idx] {
			t.Fatalf("Expected to receive %v, instead received %v", payload, recvBuf[0])
		}
	}
}

func TestReadEnd(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()
	otherSt := NewMultihopTun(stIp, virtualIp, remotePort, 1280)

	readerDev := device.NewDevice(&st, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	otherDev := device.NewDevice(&otherSt, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configureDevices(t, readerDev, otherDev)

	readerDev.Up()
	receivers, port, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open UDP socket: %s", err)
	}
	if len(receivers) != 1 {
		t.Fatalf("Expected 1 receiver func, got %v", len(receivers))
	}

	if port == 0 {
		t.Fatalf("Expected a random port to be assigned, instead got 0")
	}

	buf := [][]byte{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}

	err = stBind.Send(buf, nil)
	if err != nil {
		t.Fatalf("Error when sending UDP traffic: %v", err)
	}
}

func TestMultihopTunWrite(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	receivers, port, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open UDP socket: %s", err)
	}
	if len(receivers) != 1 {
		t.Fatalf("Expected 1 receiver func, got %v", len(receivers))
	}

	if port == 0 {
		t.Fatalf("Expected a random port to be assigned, instead got 0")
	}

	udpPacket := [][]byte{{69, 0, 0, 32, 164, 27, 0, 0, 64, 17, 206, 165, 1, 2, 3, 5, 1, 2, 3, 4, 209, 129, 19, 141, 0, 12, 0, 0, 1, 2, 3, 4}}

	if err != nil {
		t.Fatalf("Error when sending UDP traffic: %v", err)
	}
	go func() {
		st.Write(udpPacket, 0)
	}()

	buf := make([][]byte, 1600)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	_, err = receivers[0](buf, sizes, eps)
	packetSize := sizes[0]
	if err != nil {
		t.Fatalf("Failed to receive packets: %s", err)
	}

	expected := []byte{1, 2, 3, 4}
	if len(buf[:packetSize]) != len(expected) {
		t.Fatalf("Expected %v, got %v", expected, buf[0])
	}

	for b := range buf[:packetSize] {
		if buf[0][b] != expected[b] {
			t.Fatalf("Expected %v, got %v", expected, buf[0])
		}
	}
}

func TestMultihopTunRead(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	_, _, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open UDP socket: %s", err)
	}

	payload := [][]byte{{1, 2, 3, 4}}
	go stBind.Send(payload, nil)

	bytes := make([][]byte, 1500, 1500)
	sizes := make([]int, 1)
	_, err = st.Read(bytes, sizes, 0)
	bytesRead := sizes[0]
	if err != nil {
		t.Fatalf("Failed to read from tunnel device: %v", err)
	}

	packet := header.IPv4(bytes[0][:bytesRead])
	virtualIpBytes, _ := virtualIp.MarshalBinary()
	stIpBytes, _ := stIp.MarshalBinary()

	if packet.SourceAddress() != tcpip.AddrFromSlice(stIpBytes) {
		t.Fatalf("expected %v, got %v", stIp, packet.SourceAddress())
	}

	if packet.DestinationAddress() != tcpip.AddrFromSlice(virtualIpBytes) {
		t.Fatalf("expected %v, got %v", virtualIp, packet.DestinationAddress())
	}

}

func configureDevices(t testing.TB, aDev *device.Device, bDev *device.Device) {
	configs, endpointConfigs, _ := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	aDev.IpcSet(aConfig)
	bDev.IpcSet(bConfig)
}

func genConfigsForMultihop(t testing.TB) ([4]string, [4]uint16) {
	entryConfigs, entryEndpoints, entryPorts := genConfigs(t)
	exitConfigs, exitEndpoints, exitPorts := genConfigs(t)

	aExitConfig := exitConfigs[0] + exitEndpoints[0]
	bExitConfig := exitConfigs[1] + exitEndpoints[1]
	aEntryConfig := entryConfigs[0] + entryEndpoints[0]
	bEntryConfig := entryConfigs[1] + entryEndpoints[1]

	ports := [4]uint16{entryPorts[0], exitPorts[0], exitPorts[1], entryPorts[1]}

	return [4]string{aEntryConfig, aExitConfig, bExitConfig, bEntryConfig}, ports

}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB) (cfgs, endpointCfgs [2]string, ports [2]uint16) {
	var key1, key2 device.NoisePrivateKey

	_, err := rand.Read(key1[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}

	ports[0] = getFreeLocalUdpPort(tb)
	ports[1] = getFreeLocalUdpPort(tb)

	pub1, pub2 := publicKey(&key1), publicKey(&key2)

	cfgs[0] = uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", fmt.Sprintf("%d", ports[0]),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)
	endpointCfgs[0] = uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", ports[1]),
	)
	cfgs[1] = uapiCfg(
		"private_key", hex.EncodeToString(key2[:]),
		"listen_port", fmt.Sprintf("%d", ports[1]),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub1[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)
	endpointCfgs[1] = uapiCfg(
		"public_key", hex.EncodeToString(pub1[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", ports[0]),
	)
	return
}

func publicKey(sk *device.NoisePrivateKey) (pk device.NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func getFreeLocalUdpPort(t testing.TB) uint16 {
	localAddr := netip.MustParseAddrPort("127.0.0.1:0")
	udpSockAddr := net.UDPAddrFromAddrPort(localAddr)
	udpConn, err := net.ListenUDP("udp4", udpSockAddr)
	if err != nil {
		t.Fatalf("Failed to open a UDP socket to assign an empty port")
	}
	defer udpConn.Close()

	port := netip.MustParseAddrPort(udpConn.LocalAddr().String()).Port()

	return port
}

func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

func TestShutdown(t *testing.T) {
	a, b := generateTestPair(t)
	b.Close()
	a.Close()
}

func TestReversedShutdown(t *testing.T) {
	a, b := generateTestPair(t)
	a.Close()
	b.Close()
}

func generateTestPair(t *testing.T) (*device.Device, *device.Device) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	virtualDev, virtualNet, _ := netstack.CreateNetTUN([]netip.Addr{virtualIp}, []netip.Addr{}, 1280)

	readerDev := device.NewDevice(virtualDev, stBind, device.NewLogger(device.LogLevelSilent, ""))
	otherDev := device.NewDevice(&st, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configureDevices(t, readerDev, otherDev)

	readerDev.Up()
	otherDev.Up()

	conn, err := virtualNet.Dial("ping4", "10.64.0.1")
	requestPing := icmp.Echo{
		Seq:  345,
		Data: []byte("gopher burrow"),
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	conn.SetReadDeadline(time.Now().Add(time.Second * 9))
	_, err = conn.Write(icmpBytes)
	if err != nil {
		t.Fatal(err)
	}

	return readerDev, otherDev
}

func TestShutdownBind(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	binder := st.Binder()
	recvFunc, _, err := binder.Open(0)
	if err != nil {
		t.Fatalf("Failed to open a UDP socket, %v", err)
	}

	st.Close()

	buf := make([][]byte, 1600)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	_, err = recvFunc[0](buf, sizes, eps)
	neterr, ok := err.(net.Error)
	if !ok {
		t.Fatalf("Expected a net.Error, instead got %v", err)
	}
	if neterr.Temporary() {
		t.Fatalf("Expected the net error to not be temporary")
	}
}

func TestMultihopLocally(t *testing.T) {
	aVirtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	bVirtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})

	configsForMultihop, ports := genConfigsForMultihop(t)

	multihopA := NewMultihopTun(aVirtualIp, netip.MustParseAddr(fmt.Sprintf("127.0.0.1")), ports[3], 1280)
	multihopB := NewMultihopTun(bVirtualIp, netip.MustParseAddr(fmt.Sprintf("127.0.0.1")), ports[0], 1280)
	aBinder := multihopA.Binder()
	bBinder := multihopB.Binder()

	virtualDevA, virtualNetA, _ := netstack.CreateNetTUN([]netip.Addr{aVirtualIp}, []netip.Addr{}, 1280)
	virtualDevB, virtualNetB, _ := netstack.CreateNetTUN([]netip.Addr{bVirtualIp}, []netip.Addr{}, 1280)

	aExitDevice := device.NewDevice(virtualDevA, aBinder, device.NewLogger(device.LogLevelVerbose, ""))
	aExitDevice.IpcSet(configsForMultihop[0])

	aEntryDevice := device.NewDevice(&multihopA, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	aEntryDevice.IpcSet(configsForMultihop[1])

	bEntryDevice := device.NewDevice(&multihopB, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	bEntryDevice.IpcSet(configsForMultihop[2])

	bExitDevice := device.NewDevice(virtualDevB, bBinder, device.NewLogger(device.LogLevelVerbose, ""))
	bExitDevice.IpcSet(configsForMultihop[3])

	err := aExitDevice.Up()
	if err != nil {
		t.Fatalf("exit device a failed to up itself: %v", err)
	}

	err = aEntryDevice.Up()
	if err != nil {
		t.Fatalf("entry device a failed to up itself: %v", err)
	}

	err = bExitDevice.Up()
	if err != nil {
		t.Fatalf("exit device b failed to up itself: %v", err)
	}

	err = bEntryDevice.Up()
	if err != nil {
		t.Fatalf("entry device b failed to up itself: %v", err)
	}

	listenerAddr := netip.AddrPortFrom(bVirtualIp, 7070)
	senderAddr := netip.AddrPortFrom(aVirtualIp, 4040)
	listenerSocket, err := virtualNetB.ListenUDPAddrPort(netip.AddrPortFrom(bVirtualIp, 7070))
	if err != nil {
		t.Fatalf("Fail to open listener socket: %v", err)
	}

	senderSocket, err := virtualNetA.DialUDPAddrPort(senderAddr, listenerAddr)
	if err != nil {
		t.Fatalf("Failed to open sender socket: %v", err)
	}

	payload := []byte{1, 2, 3, 4, 5}

	n, err := senderSocket.Write(payload)
	if err != nil {
		t.Fatalf("Failed to send payload: %v", err)
	}

	if n != len(payload) {
		t.Fatalf("Expected to send %v bytes, instead sent %v", len(payload), n)
	}

	rxBuffer := []byte{1, 2, 3, 4, 5}
	n, err = listenerSocket.Read(rxBuffer)
	if err != nil {
		t.Fatalf("Failed to receive payload: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Expected to read %v bytes, instead read %v bytes", len(payload), n)
	}

	for idx := range rxBuffer {
		if rxBuffer[idx] != payload[idx] {
			t.Fatalf("At index %d, expected value %d, instead got %v", idx, rxBuffer[idx], payload[idx])
		}
	}

	aEntryDevice.Close()
	aExitDevice.Close()
	bEntryDevice.Close()
	bExitDevice.Close()
}
