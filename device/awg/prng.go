package awg

import (
	crand "crypto/rand"
	v2 "math/rand/v2"

	"golang.org/x/exp/constraints"
)

type RandomNumberGenerator[T constraints.Integer] interface {
	RandomSizeInRange(min, max T) T
	Get() uint64
	ReadSize(size int) []byte
}

type PRNG[T constraints.Integer] struct {
	cha8Rand *v2.ChaCha8
}

func NewPRNG[T constraints.Integer]() PRNG[T] {
	buf := make([]byte, 32)
	_, _ = crand.Read(buf)

	return PRNG[T]{
		cha8Rand: v2.NewChaCha8([32]byte(buf)),
	}
}

func (p PRNG[T]) RandomSizeInRange(min, max T) T {
	if min > max {
		panic("min must be less than max")
	}

	if min == max {
		return min
	}

	return T(p.Get()%uint64(max-min)) + min
}

func (p PRNG[T]) Get() uint64 {
	return p.cha8Rand.Uint64()
}

func (p PRNG[T]) ReadSize(size int) []byte {
	// TODO: use a memory pool to allocate
	buf := make([]byte, size)
	_, _ = p.cha8Rand.Read(buf)
	return buf
}
