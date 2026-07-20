/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
	HeaderCipherKeySize   = 32
	HeaderCipherSaltSize  = 8
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
	HeaderCipherKey   [HeaderCipherKeySize]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key HeaderCipherKey) IsZero() bool {
	var zero HeaderCipherKey
	return key.Equals(zero)
}

func (key HeaderCipherKey) Equals(tar HeaderCipherKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *HeaderCipherKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

var (
	_ (HeaderCipher) = (*headerCipherImpl)(nil)
	_ (HeaderCipher) = (*headerCipherStub)(nil)
)

type HeaderCipher interface {
	Apply(data []byte)
	Crypt(data []byte) []byte
}

type headerCipherImpl struct {
	hash      [blake2s.Size]byte
	bytesUsed int
}

func (h *headerCipherImpl) Apply(data []byte) {
	for i := range data {
		data[i] = data[i] ^ h.hash[h.bytesUsed]
		h.bytesUsed++
	}
}

func (h *headerCipherImpl) Crypt(data []byte) []byte {
	res := make([]byte, len(data))
	for i := range data {
		res[i] = data[i] ^ h.hash[i]
	}
	return res
}

type headerCipherStub struct {
}

func (*headerCipherStub) Apply(data []byte) {

}

func (*headerCipherStub) Crypt(data []byte) []byte {
	return data
}

type UintRange struct {
	hi, lo uint32
}

func (r *UintRange) FromString(str string) error {
	parts := strings.Split(str, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return errors.New("wrong format")
	}

	lo, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return err
	}

	hi := lo
	if len(parts) > 1 {
		hi, err = strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return err
		}
	}

	r.lo = uint32(lo)
	r.hi = uint32(hi)
	return nil
}

func (r *UintRange) IsZero() bool {
	return r.hi == 0 && r.lo == 0
}

func (r *UintRange) PickOne() uint32 {
	return randUint(r.lo, r.hi)
}

func (r *UintRange) ToString() string {
	if r.lo == r.hi {
		return fmt.Sprintf("%d", r.lo)
	} else {
		return fmt.Sprintf("%d-%d", r.lo, r.hi)
	}
}
