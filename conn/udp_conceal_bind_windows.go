//go:build windows

package conn

var _ BindSocketToInterface = (*ConcealBind)(nil)

func (b *ConcealBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	bindable, ok := b.inner.(BindSocketToInterface)
	if !ok {
		return nil
	}
	return bindable.BindSocketToInterface4(interfaceIndex, blackhole)
}

func (b *ConcealBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	bindable, ok := b.inner.(BindSocketToInterface)
	if !ok {
		return nil
	}
	return bindable.BindSocketToInterface6(interfaceIndex, blackhole)
}
