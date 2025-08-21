/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	if !tempAwg.Cfg.IsSet && !tempAwg.HandshakeHandler.IsSet {
		return nil
	}

	var errs []error

	isAwgOn := false
	device.awg.Mux.Lock()
	if tempAwg.Cfg.JunkPacketCount < 0 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketCount should be non negative",
		),
		)
	}
	device.awg.Cfg.JunkPacketCount = tempAwg.Cfg.JunkPacketCount
	if tempAwg.Cfg.JunkPacketCount != 0 {
		isAwgOn = true
	}

	device.awg.Cfg.JunkPacketMinSize = tempAwg.Cfg.JunkPacketMinSize
	if tempAwg.Cfg.JunkPacketMinSize != 0 {
		isAwgOn = true
	}

	if device.awg.Cfg.JunkPacketCount > 0 &&
		tempAwg.Cfg.JunkPacketMaxSize == tempAwg.Cfg.JunkPacketMinSize {

		tempAwg.Cfg.JunkPacketMaxSize++ // to make rand gen work
	}

	if tempAwg.Cfg.JunkPacketMaxSize >= MaxSegmentSize {
		device.awg.Cfg.JunkPacketMinSize = 0
		device.awg.Cfg.JunkPacketMaxSize = 1
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketMaxSize: %d; should be smaller than maxSegmentSize: %d",
			tempAwg.Cfg.JunkPacketMaxSize,
			MaxSegmentSize,
		))
	} else if tempAwg.Cfg.JunkPacketMaxSize < tempAwg.Cfg.JunkPacketMinSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"maxSize: %d; should be greater than minSize: %d",
			tempAwg.Cfg.JunkPacketMaxSize,
			tempAwg.Cfg.JunkPacketMinSize,
		))
	} else {
		device.awg.Cfg.JunkPacketMaxSize = tempAwg.Cfg.JunkPacketMaxSize
	}

	if tempAwg.Cfg.JunkPacketMaxSize != 0 {
		isAwgOn = true
	}

	magicHeaders := make([]awg.MagicHeader, 4)

	if len(tempAwg.Cfg.MagicHeaders.Values) != 4 {
		return ipcErrorf(
			ipc.IpcErrorInvalid,
			"magic headers should have 4 values; got: %d",
			len(tempAwg.Cfg.MagicHeaders.Values),
		)
	}

	if tempAwg.Cfg.MagicHeaders.Values[0].Min > 4 {
		isAwgOn = true
		device.log.Verbosef("UAPI: Updating init_packet_magic_header")
		magicHeaders[0] = tempAwg.Cfg.MagicHeaders.Values[0]

		MessageInitiationType = magicHeaders[0].Min
	} else {
		device.log.Verbosef("UAPI: Using default init type")
		MessageInitiationType = DefaultMessageInitiationType
		magicHeaders[0] = awg.NewMagicHeaderSameValue(DefaultMessageInitiationType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[1].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating response_packet_magic_header")
		magicHeaders[1] = tempAwg.Cfg.MagicHeaders.Values[1]
		MessageResponseType = magicHeaders[1].Min
	} else {
		device.log.Verbosef("UAPI: Using default response type")
		MessageResponseType = DefaultMessageResponseType
		magicHeaders[1] = awg.NewMagicHeaderSameValue(DefaultMessageResponseType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[2].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating underload_packet_magic_header")
		magicHeaders[2] = tempAwg.Cfg.MagicHeaders.Values[2]
		MessageCookieReplyType = magicHeaders[2].Min
	} else {
		device.log.Verbosef("UAPI: Using default underload type")
		MessageCookieReplyType = DefaultMessageCookieReplyType
		magicHeaders[2] = awg.NewMagicHeaderSameValue(DefaultMessageCookieReplyType)
	}

	if tempAwg.Cfg.MagicHeaders.Values[3].Min > 4 {
		isAwgOn = true

		device.log.Verbosef("UAPI: Updating transport_packet_magic_header")
		magicHeaders[3] = tempAwg.Cfg.MagicHeaders.Values[3]
		MessageTransportType = magicHeaders[3].Min
	} else {
		device.log.Verbosef("UAPI: Using default transport type")
		MessageTransportType = DefaultMessageTransportType
		magicHeaders[3] = awg.NewMagicHeaderSameValue(DefaultMessageTransportType)
	}

	var err error
	device.awg.Cfg.MagicHeaders, err = awg.NewMagicHeaders(magicHeaders)
	if err != nil {
		errs = append(errs, ipcErrorf(ipc.IpcErrorInvalid, "new magic headers: %w", err))
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

	newInitSize := MessageInitiationSize + tempAwg.Cfg.InitHeaderJunkSize

	if newInitSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`init header size(148) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.InitHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.InitHeaderJunkSize = tempAwg.Cfg.InitHeaderJunkSize
	}

	if tempAwg.Cfg.InitHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newResponseSize := MessageResponseSize + tempAwg.Cfg.ResponseHeaderJunkSize

	if newResponseSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`response header size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.ResponseHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.ResponseHeaderJunkSize = tempAwg.Cfg.ResponseHeaderJunkSize
	}

	if tempAwg.Cfg.ResponseHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newCookieSize := MessageCookieReplySize + tempAwg.Cfg.CookieReplyHeaderJunkSize

	if newCookieSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`cookie reply size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.CookieReplyHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.CookieReplyHeaderJunkSize = tempAwg.Cfg.CookieReplyHeaderJunkSize
	}

	if tempAwg.Cfg.CookieReplyHeaderJunkSize != 0 {
		isAwgOn = true
	}

	newTransportSize := MessageTransportSize + tempAwg.Cfg.TransportHeaderJunkSize

	if newTransportSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`transport size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.Cfg.TransportHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.Cfg.TransportHeaderJunkSize = tempAwg.Cfg.TransportHeaderJunkSize
	}

	if tempAwg.Cfg.TransportHeaderJunkSize != 0 {
		isAwgOn = true
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
			MessageInitiationType:  device.awg.Cfg.InitHeaderJunkSize,
			MessageResponseType:    device.awg.Cfg.ResponseHeaderJunkSize,
			MessageCookieReplyType: device.awg.Cfg.CookieReplyHeaderJunkSize,
			MessageTransportType:   device.awg.Cfg.TransportHeaderJunkSize,
		}

		packetSizeToMsgType = map[int]uint32{
			newInitSize:      MessageInitiationType,
			newResponseSize:  MessageResponseType,
			newCookieSize:    MessageCookieReplyType,
			newTransportSize: MessageTransportType,
		}
	}

	device.awg.IsOn.SetTo(isAwgOn)
	device.awg.JunkCreator = awg.NewJunkCreator(device.awg.Cfg)

	if tempAwg.HandshakeHandler.IsSet {
		if err := tempAwg.HandshakeHandler.Validate(); err != nil {
			errs = append(errs, ipcErrorf(
				ipc.IpcErrorInvalid, "handshake handler validate: %w", err))
		} else {
			device.awg.HandshakeHandler = tempAwg.HandshakeHandler
			device.awg.HandshakeHandler.SpecialJunk.DefaultJunkCount = tempAwg.Cfg.JunkPacketCount
			device.version = VersionAwgSpecialHandshake
		}
	} else {
		device.version = VersionAwg
	}

	device.awg.Mux.Unlock()

	return errors.Join(errs...)
}

func (device *Device) ProcessAWGPacket(size int, packet *[]byte, buffer *[MaxMessageSize]byte) (uint32, error) {
	// TODO:
	// if awg.WaitResponse.ShouldWait.IsSet() {
	// 	awg.WaitResponse.Channel <- struct{}{}
	// }

	expectedMsgType, isKnownSize := packetSizeToMsgType[size]
	if !isKnownSize {
		msgType, err := device.handleTransport(size, packet, buffer)

		if err != nil {
			return 0, fmt.Errorf("handle transport: %w", err)
		}

		return msgType, nil
	}

	junkSize := msgTypeToJunkSize[expectedMsgType]

	// transport size can align with other header types;
	// making sure we have the right actualMsgType
	actualMsgType, err := device.getMsgType(packet, junkSize)
	if err != nil {
		return 0, fmt.Errorf("get msg type: %w", err)
	}

	if actualMsgType == expectedMsgType {
		*packet = (*packet)[junkSize:]
		return actualMsgType, nil
	}

	device.log.Verbosef("awg: transport packet lined up with another msg type")

	msgType, err := device.handleTransport(size, packet, buffer)
	if err != nil {
		return 0, fmt.Errorf("handle transport: %w", err)
	}

	return msgType, nil
}

func (device *Device) getMsgType(packet *[]byte, junkSize int) (uint32, error) {
	msgTypeValue := binary.LittleEndian.Uint32((*packet)[junkSize : junkSize+4])
	msgType, err := device.awg.GetMagicHeaderMinFor(msgTypeValue)

	if err != nil {
		return 0, fmt.Errorf("get magic header min: %w", err)
	}

	return msgType, nil
}

func (device *Device) handleTransport(size int, packet *[]byte, buffer *[MaxMessageSize]byte) (uint32, error) {
	junkSize := device.awg.Cfg.TransportHeaderJunkSize

	msgType, err := device.getMsgType(packet, junkSize)
	if err != nil {
		return 0, fmt.Errorf("get msg type: %w", err)
	}

	if msgType != MessageTransportType {
		// probably a junk packet
		return 0, fmt.Errorf("Received message with unknown type: %d", msgType)
	}

	if junkSize > 0 {
		// remove junk from buffer by shifting the packet
		// this buffer is also used for decryption, so it needs to be corrected
		copy((*buffer)[:size], (*packet)[junkSize:])
		size -= junkSize
		// need to reinitialize packet as well
		(*packet) = (*packet)[:size]
	}

	return msgType, nil
}
