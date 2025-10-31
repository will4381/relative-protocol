//go:build ios

package bridge

import "runtime/debug"

const (
	// iosMemoryLimit is the hard heap ceiling enforced for the Network Extension
	// process. Stay comfortably below the 40 MiB jetsam watermark.
	iosMemoryLimit = 32 << 20
	iosGCPercent   = 50
)

func init() {
	debug.SetMemoryLimit(iosMemoryLimit)
	debug.SetGCPercent(iosGCPercent)
}
