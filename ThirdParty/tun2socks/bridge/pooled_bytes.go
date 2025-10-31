package bridge

import (
	"github.com/xjasonlyu/tun2socks/v2/buffer"
)

// pooledBytes tracks a payload clone that may be backed by the shared buffer
// allocator. Call release when the slice is no longer needed so the buffer can
// be recycled.
type pooledBytes struct {
	data   []byte
	pooled bool
}

// newPooledBytes clones src and attempts to serve it out of the shared buffer
// allocator to avoid repeated heap churn.
func newPooledBytes(src []byte) pooledBytes {
	size := len(src)
	if size == 0 {
		return pooledBytes{}
	}
	buf := buffer.Get(size)
	if buf != nil {
		copy(buf, src)
		return pooledBytes{
			data:   buf,
			pooled: true,
		}
	}
	cloned := append([]byte(nil), src...)
	return pooledBytes{
		data:   cloned,
		pooled: false,
	}
}

func (p *pooledBytes) bytes() []byte {
	if p == nil {
		return nil
	}
	return p.data
}

func (p *pooledBytes) release() {
	if p == nil || p.data == nil {
		return
	}
	if p.pooled {
		// Restore the slice to full capacity before returning to the allocator.
		buffer.Put(p.data[:cap(p.data)])
	}
	p.data = nil
	p.pooled = false
}
