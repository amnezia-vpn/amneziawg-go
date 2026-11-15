//go:build !android

package uidfilter

// Supported is false everywhere except Android: no other platform has a way to
// resolve the owning app of a connection, so no filter can be installed. See
// supported_android.go.
const Supported = false
