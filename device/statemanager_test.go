/*
 * Copyright (c) 2022. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package device

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var timeMs int64 = 0
var mockDevice MockDevice
var manager *WireGuardStateManager
var lastState WireGuardState

type MockDevice struct {
	isUp    bool
	upCount int
}

func (dev *MockDevice) Up() error {
	dev.isUp = true
	dev.upCount++
	return nil
}

func (dev *MockDevice) Down() error {
	dev.isUp = false
	return nil
}

func setup() {
	timeMs = 0
	timeNow = func() time.Time { return time.UnixMilli(timeMs) }
	mockDevice.isUp = false

	manager = NewWireGuardStateManager(NewLogger(LogLevelVerbose, ""), "tcp")
	manager.Start(&mockDevice)
	lastState = WireGuardDisabled
	go func() {
		for lastState != -1 {
			lastState = manager.GetState()
		}
	}()
}

func setdown() {
	manager.Close()
}

func TestWireGuardStateManager_shouldRestart(t *testing.T) {
	assert := assert.New(t)
	setup()
	defer setdown()

	assert.Equal(initialRestartDelay, manager.nextRestartDelay)

	assert.Equal(false, manager.shouldRestart())
	timeMs += initialRestartDelay.Milliseconds()
	assert.Equal(false, manager.shouldRestart())
	timeMs += 1
	assert.Equal(true, manager.shouldRestart())

	assert.Equal(2*initialRestartDelay, manager.nextRestartDelay)
	assert.Equal(false, manager.shouldRestart())
	timeMs += 2 * initialRestartDelay.Milliseconds()
	assert.Equal(false, manager.shouldRestart())
	timeMs += 1
	assert.Equal(true, manager.shouldRestart())

	timeMs += resetRestartDelay.Milliseconds() + 1
	assert.Equal(true, manager.shouldRestart())
	assert.Equal(initialRestartDelay, manager.nextRestartDelay)
}

func TestWireGuardStateManager_networkStartsAndStopsDevice(t *testing.T) {
	assert := assert.New(t)
	setup()
	defer setdown()

	assert.Equal(false, mockDevice.isUp)
	manager.SetNetworkAvailable(true)
	time.Sleep(time.Millisecond) // Poor substitute for advanceUntilIdle, make sure goroutines finish before checking
	assert.Equal(true, mockDevice.isUp)
	assert.Equal(WireGuardConnecting, lastState)
	manager.SetNetworkAvailable(false)
	time.Sleep(time.Millisecond)
	assert.Equal(WireGuardWaitingForNetwork, lastState)
	assert.Equal(false, mockDevice.isUp)
}

func TestWireGuardStateManager_happyConnectionPath(t *testing.T) {
	assert := assert.New(t)
	setup()
	defer setdown()

	manager.SetNetworkAvailable(true)
	time.Sleep(time.Millisecond)
	manager.HandshakeStateChan <- HandshakeSuccess
	time.Sleep(time.Millisecond)
	assert.Equal(WireGuardConnected, lastState)
	assert.Equal(true, mockDevice.isUp)
}

func TestWireGuardStateManager_handshakeFailCausesRestart(t *testing.T) {
	assert := assert.New(t)
	setup()
	defer setdown()

	manager.SetNetworkAvailable(true)
	time.Sleep(time.Millisecond)
	manager.HandshakeStateChan <- HandshakeFail
	time.Sleep(time.Millisecond)
	assert.Equal(WireGuardError, lastState)
	timeMs += initialRestartDelay.Milliseconds() + 1
	manager.HandshakeStateChan <- HandshakeFail
	time.Sleep(time.Millisecond)
	assert.Equal(WireGuardConnecting, lastState)
	assert.Equal(2, mockDevice.upCount)
}

func TestWireGuardStateManager_brokenPipeCausesRestart(t *testing.T) {
	assert := assert.New(t)
	setup()
	defer setdown()

	manager.SetNetworkAvailable(true)
	timeMs += initialRestartDelay.Milliseconds() + 1
	time.Sleep(time.Millisecond)
	manager.SocketErrChan <- errors.New("broken pipe")
	time.Sleep(time.Millisecond)
	assert.Equal(WireGuardConnecting, lastState)
	assert.Equal(2, mockDevice.upCount)
}
