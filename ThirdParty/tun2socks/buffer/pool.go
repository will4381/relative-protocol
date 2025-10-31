// Package buffer provides a pool of []byte.
package buffer

import (
	"github.com/xjasonlyu/tun2socks/v2/buffer/allocator"
)

const (
	// MaxSegmentSize is the largest possible UDP datagram size.
	MaxSegmentSize = (1 << 16) - 1

	// RelayBufferSize is the default buffer size for TCP relays.
	// Align with io.Copy defaults while keeping buffers within the 32–64 KiB
	// window recommended for iOS tunnel targets.
	RelayBufferSize = 32 << 10
)

var _allocator = allocator.New()

// Get gets a []byte from default allocator with most appropriate cap.
func Get(size int) []byte {
	return _allocator.Get(size)
}

// Put returns a []byte to default allocator for future use.
func Put(buf []byte) error {
	return _allocator.Put(buf)
}
