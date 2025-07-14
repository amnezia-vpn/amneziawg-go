/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device/awg"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/ratelimiter"
	"github.com/amnezia-vpn/amneziawg-go/rwcancel"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

type Version uint8

const (
	VersionDefault Version = iota
	VersionAwg
	VersionAwgSpecialHandshake
)

// TODO:
type AtomicVersion struct {
	value atomic.Uint32
}

func NewAtomicVersion(v Version) *AtomicVersion {
	av := &AtomicVersion{}
	av.Store(v)
	return av
}

func (av *AtomicVersion) Load() Version {
	return Version(av.value.Load())
}

func (av *AtomicVersion) Store(v Version) {
	av.value.Store(uint32(v))
}

func (av *AtomicVersion) CompareAndSwap(old, new Version) bool {
	return av.value.CompareAndSwap(uint32(old), uint32(new))
}

func (av *AtomicVersion) Swap(new Version) Version {
	return Version(av.value.Swap(uint32(new)))
}

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
		brokenRoaming bool
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	pool struct {
		inboundElementsContainer  *WaitPool
		outboundElementsContainer *WaitPool
		messageBuffers            *WaitPool
		inboundElements           *WaitPool
		outboundElements          *WaitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device tun.Device
		mtu    atomic.Int32
	}

	ipcMutex sync.RWMutex
	closed   chan struct{}
	log      *Logger

	version Version
	awg     awg.Protocol
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// Must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	device.log.Verbosef(
		"Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start()
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // One for each RoutineHandshake
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1)
		go device.RoutineDecryption(i + 1)
		go device.RoutineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if device.isClosed() {
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	device.tun.device.Close()
	device.downLocked()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	device.RemoveAllPeers()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait()

	device.rate.limiter.Close()

	device.resetProtocol()

	device.log.Verbosef("Device closed")
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	if !device.isUp() {
		return nil
	}

	// bind to new port
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
		netc.port = 0
		return err
	}

	// set fwmark
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}
func (device *Device) isAWG() bool {
	return device.version >= VersionAwg
}

func (device *Device) resetProtocol() {
	// restore default message type values
	MessageInitiationType = DefaultMessageInitiationType
	MessageResponseType = DefaultMessageResponseType
	MessageCookieReplyType = DefaultMessageCookieReplyType
	MessageTransportType = DefaultMessageTransportType
}

func (device *Device) handlePostConfig(tempAwg *awg.Protocol) error {
	if !tempAwg.ASecCfg.IsSet && !tempAwg.HandshakeHandler.IsSet {
		return nil
	}

	var errs []error

	isASecOn := false
	device.awg.ASecMux.Lock()
	if tempAwg.ASecCfg.JunkPacketCount < 0 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketCount should be non negative",
		),
		)
	}
	device.awg.ASecCfg.JunkPacketCount = tempAwg.ASecCfg.JunkPacketCount
	if tempAwg.ASecCfg.JunkPacketCount != 0 {
		isASecOn = true
	}

	device.awg.ASecCfg.JunkPacketMinSize = tempAwg.ASecCfg.JunkPacketMinSize
	if tempAwg.ASecCfg.JunkPacketMinSize != 0 {
		isASecOn = true
	}

	if device.awg.ASecCfg.JunkPacketCount > 0 &&
		tempAwg.ASecCfg.JunkPacketMaxSize == tempAwg.ASecCfg.JunkPacketMinSize {

		tempAwg.ASecCfg.JunkPacketMaxSize++ // to make rand gen work
	}

	if tempAwg.ASecCfg.JunkPacketMaxSize >= MaxSegmentSize {
		device.awg.ASecCfg.JunkPacketMinSize = 0
		device.awg.ASecCfg.JunkPacketMaxSize = 1
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketMaxSize: %d; should be smaller than maxSegmentSize: %d",
			tempAwg.ASecCfg.JunkPacketMaxSize,
			MaxSegmentSize,
		))
	} else if tempAwg.ASecCfg.JunkPacketMaxSize < tempAwg.ASecCfg.JunkPacketMinSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"maxSize: %d; should be greater than minSize: %d",
			tempAwg.ASecCfg.JunkPacketMaxSize,
			tempAwg.ASecCfg.JunkPacketMinSize,
		))
	} else {
		device.awg.ASecCfg.JunkPacketMaxSize = tempAwg.ASecCfg.JunkPacketMaxSize
	}

	if tempAwg.ASecCfg.JunkPacketMaxSize != 0 {
		isASecOn = true
	}

	newInitSize := MessageInitiationSize + tempAwg.ASecCfg.InitHeaderJunkSize

	if newInitSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`init header size(148) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.InitHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.InitHeaderJunkSize = tempAwg.ASecCfg.InitHeaderJunkSize
	}

	if tempAwg.ASecCfg.InitHeaderJunkSize != 0 {
		isASecOn = true
	}

	newResponseSize := MessageResponseSize + tempAwg.ASecCfg.ResponseHeaderJunkSize

	if newResponseSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`response header size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.ResponseHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.ResponseHeaderJunkSize = tempAwg.ASecCfg.ResponseHeaderJunkSize
	}

	if tempAwg.ASecCfg.ResponseHeaderJunkSize != 0 {
		isASecOn = true
	}

	newCookieSize := MessageCookieReplySize + tempAwg.ASecCfg.CookieReplyHeaderJunkSize

	if newCookieSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`cookie reply size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.CookieReplyHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.CookieReplyHeaderJunkSize = tempAwg.ASecCfg.CookieReplyHeaderJunkSize
	}

	if tempAwg.ASecCfg.CookieReplyHeaderJunkSize != 0 {
		isASecOn = true
	}

	newTransportSize := MessageTransportSize + tempAwg.ASecCfg.TransportHeaderJunkSize

	if newTransportSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`transport size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.TransportHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.TransportHeaderJunkSize = tempAwg.ASecCfg.TransportHeaderJunkSize
	}

	if tempAwg.ASecCfg.TransportHeaderJunkSize != 0 {
		isASecOn = true
	}

	if tempAwg.ASecCfg.InitPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating init_packet_magic_header")
		device.awg.ASecCfg.InitPacketMagicHeader = tempAwg.ASecCfg.InitPacketMagicHeader
		MessageInitiationType = device.awg.ASecCfg.InitPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default init type")
		MessageInitiationType = DefaultMessageInitiationType
	}

	if tempAwg.ASecCfg.ResponsePacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating response_packet_magic_header")
		device.awg.ASecCfg.ResponsePacketMagicHeader = tempAwg.ASecCfg.ResponsePacketMagicHeader
		MessageResponseType = device.awg.ASecCfg.ResponsePacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default response type")
		MessageResponseType = DefaultMessageResponseType
	}

	if tempAwg.ASecCfg.UnderloadPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating underload_packet_magic_header")
		device.awg.ASecCfg.UnderloadPacketMagicHeader = tempAwg.ASecCfg.UnderloadPacketMagicHeader
		MessageCookieReplyType = device.awg.ASecCfg.UnderloadPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default underload type")
		MessageCookieReplyType = DefaultMessageCookieReplyType
	}

	if tempAwg.ASecCfg.TransportPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating transport_packet_magic_header")
		device.awg.ASecCfg.TransportPacketMagicHeader = tempAwg.ASecCfg.TransportPacketMagicHeader
		MessageTransportType = device.awg.ASecCfg.TransportPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default transport type")
		MessageTransportType = DefaultMessageTransportType
	}

	isSameHeaderMap := map[uint32]struct{}{
		MessageInitiationType:  {},
		MessageResponseType:    {},
		MessageCookieReplyType: {},
		MessageTransportType:   {},
	}

	// size will be different if same values
	if len(isSameHeaderMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`magic headers should differ; got: init:%d; recv:%d; unde:%d; tran:%d`,
			MessageInitiationType,
			MessageResponseType,
			MessageCookieReplyType,
			MessageTransportType,
		),
		)
	}

	isSameSizeMap := map[int]struct{}{
		newInitSize:      {},
		newResponseSize:  {},
		newCookieSize:    {},
		newTransportSize: {},
	}

	if len(isSameSizeMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`new sizes should differ; init: %d; response: %d; cookie: %d; trans: %d`,
			newInitSize,
			newResponseSize,
			newCookieSize,
			newTransportSize,
		),
		)
	} else {
		msgTypeToJunkSize = map[uint32]int{
			MessageInitiationType:  device.awg.ASecCfg.InitHeaderJunkSize,
			MessageResponseType:    device.awg.ASecCfg.ResponseHeaderJunkSize,
			MessageCookieReplyType: device.awg.ASecCfg.CookieReplyHeaderJunkSize,
			MessageTransportType:   device.awg.ASecCfg.TransportHeaderJunkSize,
		}

		packetSizeToMsgType = map[int]uint32{
			newInitSize:      MessageInitiationType,
			newResponseSize:  MessageResponseType,
			newCookieSize:    MessageCookieReplyType,
			newTransportSize: MessageTransportType,
		}
	}

	device.awg.IsASecOn.SetTo(isASecOn)
	var err error
	device.awg.JunkCreator, err = awg.NewJunkCreator(device.awg.ASecCfg)
	if err != nil {
		errs = append(errs, err)
	}

	if tempAwg.HandshakeHandler.IsSet {
		if err := tempAwg.HandshakeHandler.Validate(MaxSegmentSize); err != nil {
			errs = append(errs, ipcErrorf(
				ipc.IpcErrorInvalid, "handshake handler validate: %w", err))
		} else {
			device.awg.HandshakeHandler = tempAwg.HandshakeHandler
			device.awg.HandshakeHandler.ControlledJunk.DefaultJunkCount = tempAwg.ASecCfg.JunkPacketCount
			device.awg.HandshakeHandler.SpecialJunk.DefaultJunkCount = tempAwg.ASecCfg.JunkPacketCount
			device.version = VersionAwgSpecialHandshake
		}
	} else {
		device.version = VersionAwg
	}

	device.awg.ASecMux.Unlock()

	return errors.Join(errs...)
}
