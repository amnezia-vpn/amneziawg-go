//go:build android

package uidfilter

// Supported is a build-time constant so that callers can guard the hook with
// `if uidfilter.Supported && ...`: on every other platform the compiler drops
// the branch, and with it the call, before the binary is produced.
const Supported = true
