/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	duration      time.Duration
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer, time.Duration)) *Timer {
	timer := &Timer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if timer.duration == 0 {
			timer.modifyingLock.Unlock()
			return
		}
		duration := timer.duration
		timer.modifyingLock.Unlock()
		timer.duration = 0

		expirationFunction(peer, duration)
	})
	timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.duration = d
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.duration = 0
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *Timer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.duration > 0
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *Peer, d time.Duration) {
	maxAttempts := peer.timers.maxHandshakeAttempts.Load()

	if peer.timers.handshakeAttempts.Load() > maxAttempts {
		peer.device.log.Verbosef("%s - Handshake did not complete after %d attempts, giving up", peer, maxAttempts+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(peer.device.keychainExpireTime() * 3)
		}
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(d.Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer, d time.Duration) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		}
	}
}

func expiredNewHandshake(peer *Peer, d time.Duration) {
	peer.device.log.Verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int(d.Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *Peer, d time.Duration) {
	peer.device.log.Verbosef("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int(d.Seconds()))
	peer.ZeroAndFlushAll()
}

func expiredPersistentKeepalive(peer *Peer, d time.Duration) {
	if !peer.persistentKeepaliveInterval.Load().IsZero() {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(peer.newHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Mod(peer.retransmitHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttemps())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(peer.device.keychainExpireTime() * 3)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if !keepalive.IsZero() && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive.PickOne()) * time.Second)
	}
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttemps())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}

func (peer *Peer) retransmitHandshakeTimeout() time.Duration {
	timeout := RekeyTimeout

	if t := peer.device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}

	return timeout
}

func (peer *Peer) sendKeepaliveTimeout() time.Duration {
	timeout := KeepaliveTimeout

	if t := peer.device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}

	return timeout
}

func (peer *Peer) newHandshakeTimeout() time.Duration {
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout

	if t := peer.device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Hi()) * time.Second
	}
	if t := peer.device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.PickOne()) * time.Second
	}

	return keepaliveTimeout + rekeyTimeout
}

func (device *Device) keyRefreshTimeoutSending() time.Duration {
	rekeyAfterTime := RekeyAfterTime

	if t := device.timings.rekeyAfterTimeSec.Load(); !t.IsZero() {
		rekeyAfterTime = time.Duration(t.PickOne()) * time.Second
	}

	return rekeyAfterTime
}

func (device *Device) keyRefreshTimeoutReceiving() time.Duration {
	rejectAfterTime := RejectAfterTime
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout

	if t := device.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.PickOne()) * time.Second
	}
	if t := device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Lo()) * time.Second
	}
	if t := device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}

	return max(0, rejectAfterTime-keepaliveTimeout-rekeyTimeout)
}

func (device *Device) keychainExpireTime() time.Duration {
	rejectAfterTime := RejectAfterTime

	if t := device.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.Hi()) * time.Second
	}

	return rejectAfterTime
}

func (device *Device) rekeyMinTimeout() time.Duration {
	rekeyTimeout := RekeyTimeout

	if t := device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}

	return rekeyTimeout
}

func (device *Device) maxHandshakeAttemps() uint32 {
	res := uint32(MaxTimerHandshakes)

	if t := device.timings.maxHandshakeAttemps.Load(); !t.IsZero() {
		res = t.PickOne()
	}

	return res
}
