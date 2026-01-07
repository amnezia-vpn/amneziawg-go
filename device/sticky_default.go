//go:build !linux

package device

import (
	"github.com/yury-sannikov/amneziawg-go/conn"
	"github.com/yury-sannikov/amneziawg-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
