//  buffer_pool.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Provides a simple reusable byte slice pool to minimise garbage creation
//  while packets traverse between Swift and Go.

package bridge

import "sync"

const maxPooledBufferSize = 1 << 16 // 64 KiB keeps typical MTU payloads.

var packetBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 2048)
	},
}

type packetBuffer struct {
	buf    []byte
	pooled bool
	proto  int32
}

func acquireBuffer(size int) []byte {
	buf := packetBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func releaseBuffer(buf []byte) {
	if cap(buf) > maxPooledBufferSize {
		return
	}
	packetBufferPool.Put(buf[:0])
}

func newPooledPacketBuffer(size int) packetBuffer {
	buf := acquireBuffer(size)
	return packetBuffer{
		buf:    buf[:size],
		pooled: true,
	}
}

func adoptPacketBuffer(data []byte, proto int32) packetBuffer {
	return packetBuffer{
		buf:   data,
		proto: proto,
	}
}

func (p *packetBuffer) release() {
	if p.pooled && p.buf != nil {
		releaseBuffer(p.buf)
	}
	p.buf = nil
	p.pooled = false
	p.proto = 0
}
