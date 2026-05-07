/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		if device.net.preludeOpts.Jc != 0 {
			sendf("jc=%d", device.net.preludeOpts.Jc)
		}

		if device.net.preludeOpts.Jmin != 0 {
			sendf("jmin=%d", device.net.preludeOpts.Jmin)
		}

		if device.net.preludeOpts.Jmax != 0 {
			sendf("jmax=%d", device.net.preludeOpts.Jmax)
		}

		if device.net.framedOpts.S1 != 0 {
			sendf("s1=%d", device.net.framedOpts.S1)
		}

		if device.net.framedOpts.S2 != 0 {
			sendf("s2=%d", device.net.framedOpts.S2)
		}

		if device.net.framedOpts.S3 != 0 {
			sendf("s3=%d", device.net.framedOpts.S3)
		}

		if device.net.framedOpts.S4 != 0 {
			sendf("s4=%d", device.net.framedOpts.S4)
		}

		if device.net.framedOpts.H1 != nil {
			sendf("h1=%s", device.net.framedOpts.H1.GenSpec())
		}

		if device.net.framedOpts.H2 != nil {
			sendf("h2=%s", device.net.framedOpts.H2.GenSpec())
		}

		if device.net.framedOpts.H3 != nil {
			sendf("h3=%s", device.net.framedOpts.H3.GenSpec())
		}

		if device.net.framedOpts.H4 != nil {
			sendf("h4=%s", device.net.framedOpts.H4.GenSpec())
		}

		for i, rules := range device.net.preludeOpts.RulesArr {
			if rules != nil {
				sendf("i%d=%s", i+1, rules.Spec())
			}
		}

		if len(device.net.network) > 0 {
			sendf("network=%s", device.net.network)
		}

		if device.net.masqueradeOpts.RulesIn != nil {
			sendf("format_in=%s", device.net.masqueradeOpts.RulesIn.Spec())
		}

		if device.net.masqueradeOpts.RulesOut != nil {
			sendf("format_out=%s", device.net.masqueradeOpts.RulesOut.Spec())
		}

		if device.net.fallbackPort != 0 {
			sendf("fallback_port=%d", device.net.fallbackPort)
		}

		sendf("header_compat=%s", strconv.FormatBool(device.net.framedOpts.HeaderCompat))

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval.Load())

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(
				ipc.IpcErrorProtocol,
				"failed to parse line %q",
				line,
			)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	case "jc":
		jc, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jc: %w", err)
		}
		if jc <= 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "jc must be a positive value")
		}
		device.log.Verbosef("UAPI: Updating junk count")
		device.net.preludeOpts.Jc = jc

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set junk count: %w", err)
		}

	case "jmin":
		jmin, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmin: %w", err)
		}
		if jmin <= 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmin must be a positive value")
		}

		device.log.Verbosef("UAPI: Updating junk min")
		device.net.preludeOpts.Jmin = jmin

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set junk min: %w", err)
		}

	case "jmax":
		jmax, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmax: %w", err)
		}
		if jmax <= 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmax must be a positive value")
		}

		device.log.Verbosef("UAPI: Updating junk max")
		device.net.preludeOpts.Jmax = jmax

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set junk max: %w", err)
		}

	case "s1":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s1: %w", err)
		}
		if padding < 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "s1 must be non-negative")
		}

		device.log.Verbosef("UAPI: Updating s1 padding")
		device.net.framedOpts.S1 = padding

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set s1: %w", err)
		}

	case "s2":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s2: %w", err)
		}
		if padding < 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "s2 must be non-negative")
		}

		device.log.Verbosef("UAPI: Updating s2 padding")
		device.net.framedOpts.S2 = padding

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set s2: %w", err)
		}

	case "s3":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s3: %w", err)
		}
		if padding < 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "s3 must be non-negative")
		}

		device.log.Verbosef("UAPI: Updating s3 padding")
		device.net.framedOpts.S3 = padding

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set s3: %w", err)
		}

	case "s4":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s4: %w", err)
		}
		if padding < 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "s4 must be non-negative")
		}

		device.log.Verbosef("UAPI: Updating s4 padding")
		device.net.framedOpts.S4 = padding

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set s4: %w", err)
		}

	case "h1":
		header, err := conceal.NewRangedHeader(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H1: %w", err)
		}

		opts := device.net.framedOpts
		opts.H1 = header
		if opts.HasIntersections() {
			return ipcErrorf(ipc.IpcErrorInvalid, "headers must not overlap")
		}

		device.log.Verbosef("UAPI: Updating h1 header")
		device.net.framedOpts.H1 = header

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set h1: %w", err)
		}

	case "h2":
		header, err := conceal.NewRangedHeader(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H2: %w", err)
		}

		opts := device.net.framedOpts
		opts.H2 = header
		if opts.HasIntersections() {
			return ipcErrorf(ipc.IpcErrorInvalid, "headers must not overlap")
		}

		device.log.Verbosef("UAPI: Updating h2 header")
		device.net.framedOpts.H2 = header

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set h2: %w", err)
		}

	case "h3":
		header, err := conceal.NewRangedHeader(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H3: %w", err)
		}

		opts := device.net.framedOpts
		opts.H3 = header
		if opts.HasIntersections() {
			return ipcErrorf(ipc.IpcErrorInvalid, "headers must not overlap")
		}

		device.log.Verbosef("UAPI: Updating h3 header")
		device.net.framedOpts.H3 = header

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set h3: %w", err)
		}

	case "h4":
		header, err := conceal.NewRangedHeader(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H4: %w", err)
		}

		opts := device.net.framedOpts
		opts.H4 = header
		if opts.HasIntersections() {
			return ipcErrorf(ipc.IpcErrorInvalid, "headers must not overlap")
		}

		device.log.Verbosef("UAPI: Updating h4 header")
		device.net.framedOpts.H4 = header

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set h4: %w", err)
		}

	case "i1":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse i1: %w", err)
		}

		device.net.preludeOpts.RulesArr[0] = rules

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set i1: %w", err)
		}

	case "i2":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse i2: %w", err)
		}

		device.net.preludeOpts.RulesArr[1] = rules

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set i2: %w", err)
		}

	case "i3":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse i3: %w", err)
		}

		device.net.preludeOpts.RulesArr[2] = rules

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set i3: %w", err)
		}

	case "i4":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse i4: %w", err)
		}

		device.net.preludeOpts.RulesArr[3] = rules

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set i4: %w", err)
		}

	case "i5":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse i5: %w", err)
		}

		device.net.preludeOpts.RulesArr[4] = rules

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set i5: %w", err)
		}

	case "network":
		device.net.Lock()
		device.net.network = value
		device.net.Unlock()

		device.log.Verbosef("UAPI: Updating network")

		if err := device.BindUpdate(); err != nil {
			// TODO: change IpcErrorPortInUse to something reasonable
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set network: %w", err)
		}

	case "format_in":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rules: %w", err)
		}

		device.log.Verbosef("UAPI: Updating format_in")
		device.net.masqueradeOpts.RulesIn = rules

		if err := device.BindUpdate(); err != nil {
			// TODO: change IpcErrorPortInUse to something reasonable
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set format_in: %w", err)
		}

	case "format_out":
		rules, err := conceal.ParseRules(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rules: %w", err)
		}

		device.log.Verbosef("UAPI: Updating format_out")
		device.net.masqueradeOpts.RulesOut = rules

		if err := device.BindUpdate(); err != nil {
			// TODO: change IpcErrorPortInUse to something reasonable
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set format_out: %w", err)
		}

	case "header_compat":
		compat, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse header_compat: %w", err)
		}

		device.log.Verbosef("UAPI: Updating header_compat")
		device.net.framedOpts.HeaderCompat = compat

		if err := device.BindUpdate(); err != nil {
			// TODO: change IpcErrorPortInUse to something reasonable
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set header_compat: %w", err)
		}

	case "fallback_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse fallback_port: %w", err)
		}
		if port == 0 {
			return ipcErrorf(ipc.IpcErrorInvalid, "fallback_port must be in range 1-65535")
		}

		device.log.Verbosef("UAPI: Updating fallback_port")
		device.net.fallbackPort = uint16(port)

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set fallback_port: %w", err)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(
	peer *ipcSetPeer,
	value string,
) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(
	peer *ipcSetPeer,
	key, value string,
) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set persistent keepalive interval: %w",
				err,
			)
		}

		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}
