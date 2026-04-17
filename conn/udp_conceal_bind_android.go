//go:build android

package conn

import "errors"

var _ PeekLookAtSocketFd = (*ConcealBind)(nil)

func (b *ConcealBind) PeekLookAtSocketFd4() (fd int, err error) {
	peek, ok := b.inner.(PeekLookAtSocketFd)
	if !ok {
		return -1, errors.New("peek look at socket fd unsupported")
	}
	return peek.PeekLookAtSocketFd4()
}

func (b *ConcealBind) PeekLookAtSocketFd6() (fd int, err error) {
	peek, ok := b.inner.(PeekLookAtSocketFd)
	if !ok {
		return -1, errors.New("peek look at socket fd unsupported")
	}
	return peek.PeekLookAtSocketFd6()
}
