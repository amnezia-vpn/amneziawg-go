//go:build !android

package device

const (
	tunFilterSupported = false

	// it'd be better to store inside Device, but Android will have a single Device anyway
	// and this gives guaranteed branch elimination for other platforms
	tunFilterActive = false
)

type tunFilterCacheHolder struct{}

func newTunFilterCache() tunFilterCacheHolder {
	return tunFilterCacheHolder{}
}

func (device *Device) tunFilterAllows(packet []byte) bool {
	return true
}

func (device *Device) tunFilterConfigure(value string) {}
