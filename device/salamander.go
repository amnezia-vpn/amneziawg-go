/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/blake2s"
)

const (
	salamanderSaltLen    = 8
	salamanderKeyLen     = 32
	salamanderPadHdrLen  = 2
	salamanderOverhead   = salamanderSaltLen + salamanderPadHdrLen
	salamanderPadMin     = 800
	salamanderPadMax     = 1500
	salamanderPadExtra   = 50
	salamanderMaxPadding = salamanderPadMax + salamanderPadExtra
)

func (device *Device) salamanderEnabled() bool {
	var zero NoisePresharedKey
	return subtle.ConstantTimeCompare(device.obfsPSK[:], zero[:]) != 1
}

func (device *Device) salamanderObfuscate(packet []byte) ([]byte, error) {
	if !device.salamanderEnabled() {
		return packet, nil
	}

	payloadWithHeader := len(packet) + salamanderOverhead
	target, err := randomIntInclusive(salamanderPadMin, salamanderPadMax)
	if err != nil {
		return nil, err
	}

	padLen := 0
	if payloadWithHeader < target {
		padLen = target - payloadWithHeader
	} else {
		padLen, err = randomIntInclusive(0, salamanderPadExtra)
		if err != nil {
			return nil, err
		}
	}

	out := make([]byte, salamanderOverhead+len(packet)+padLen)
	salt := out[:salamanderSaltLen]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	payload := out[salamanderSaltLen:]
	binary.LittleEndian.PutUint16(payload[:salamanderPadHdrLen], uint16(padLen))
	copy(payload[salamanderPadHdrLen:], packet)
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, payload[salamanderPadHdrLen+len(packet):]); err != nil {
			return nil, err
		}
	}

	key := device.salamanderDeriveKey(salt)
	xorWithRepeatingKey(payload, key[:])
	return out, nil
}

func (device *Device) salamanderDeobfuscate(packet []byte) ([]byte, bool) {
	if !device.salamanderEnabled() {
		return packet, true
	}
	if len(packet) <= salamanderOverhead {
		return nil, false
	}

	salt := packet[:salamanderSaltLen]
	payload := packet[salamanderSaltLen:]
	key := device.salamanderDeriveKey(salt)
	xorWithRepeatingKey(payload, key[:])

	padLen := int(binary.LittleEndian.Uint16(payload[:salamanderPadHdrLen]))
	payload = payload[salamanderPadHdrLen:]
	if padLen > len(payload) {
		return nil, false
	}
	payload = payload[:len(payload)-padLen]

	copy(packet, payload)
	return packet[:len(payload)], true
}

func (device *Device) salamanderDeriveKey(salt []byte) [salamanderKeyLen]byte {
	hash, _ := blake2s.New256(nil)
	hash.Write(device.obfsPSK[:])
	hash.Write(salt)

	var key [salamanderKeyLen]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func randomIntInclusive(min, max int) (int, error) {
	if min > max {
		return 0, errors.New("invalid random range")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + min, nil
}

func xorWithRepeatingKey(data, key []byte) {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
