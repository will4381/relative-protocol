//  tunio.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Provides a channel-backed conduit between Swift packet emission/ingestion
//  and the Go tun device abstraction.

package bridge

import (
    "errors"
    "time"
)

type tunIO struct {
    emitter PacketEmitter

    inbound chan packetBuffer
    outbound chan packetBuffer
    closed  chan struct{}
}

func newTunIO(emitter PacketEmitter) *tunIO {
    t := &tunIO{
        emitter: emitter,
        inbound:  make(chan packetBuffer, 1024),
        outbound: make(chan packetBuffer, 2048),
        closed:   make(chan struct{}),
    }
    go t.runEmitter()
    return t
}

func (t *tunIO) Read(p []byte) (int, error) {
	select {
	case packet, ok := <-t.inbound:
		if !ok {
			return 0, errors.New("tun closed")
		}
		n := copy(p, packet.buf)
		packet.release()
		return n, nil
	case <-t.closed:
		return 0, errors.New("tun closed")
	}
}

func (t *tunIO) Write(p []byte) (int, error) {
    // Copy into a pooled buffer so we can batch asynchronously.
    buf := newPooledPacketBuffer(len(p))
    copy(buf.buf, p)
    buf.proto = inferProtocol(buf.buf)
    select {
    case <-t.closed:
        buf.release()
        return 0, errors.New("tun closed")
    case t.outbound <- buf:
        return len(p), nil
    }
}

func (t *tunIO) Close() {
    select {
    case <-t.closed:
        return
    default:
        close(t.closed)
        close(t.inbound)
        close(t.outbound)
    }
}

func (t *tunIO) Inject(packet []byte, proto int32) error {
    select {
    case <-t.closed:
        return errors.New("tun closed")
    case t.inbound <- adoptPacketBuffer(packet, proto):
        return nil
    }
}

func (t *tunIO) runEmitter() {
    const maxBatch = 64
    ticker := time.NewTicker(100 * time.Microsecond)
    defer ticker.Stop()

    packets := make([][]byte, 0, maxBatch)
    protocols := make([]int32, 0, maxBatch)

    flush := func() {
        if len(packets) == 0 {
            return
        }
        // Pack packets contiguously and emit once to minimize bridge overhead.
        total := 0
        for i := range packets {
            total += len(packets[i])
        }
        packed := acquireBuffer(total)
        sizes := make([]byte, 4*len(packets))
        protos := make([]byte, 4*len(protocols))
        off := 0
        for i := range packets {
            copy(packed[off:off+len(packets[i])], packets[i])
            // encode size (little-endian int32)
            v := int32(len(packets[i]))
            sizes[i*4+0] = byte(v)
            sizes[i*4+1] = byte(v >> 8)
            sizes[i*4+2] = byte(v >> 16)
            sizes[i*4+3] = byte(v >> 24)
            // encode protocol (little-endian int32)
            pv := protocols[i]
            protos[i*4+0] = byte(pv)
            protos[i*4+1] = byte(pv >> 8)
            protos[i*4+2] = byte(pv >> 16)
            protos[i*4+3] = byte(pv >> 24)
            off += len(packets[i])
        }
        _ = t.emitter.EmitPacketBatch(packed[:total], sizes, protos)
        for i := range packets {
            releaseBuffer(packets[i])
        }
        releaseBuffer(packed)
        packets = packets[:0]
        protocols = protocols[:0]
    }

    for {
        select {
        case pb, ok := <-t.outbound:
            if !ok {
                flush()
                return
            }
            packets = append(packets, pb.buf)
            protocols = append(protocols, pb.proto)
            if len(packets) >= maxBatch {
                flush()
            }
        case <-ticker.C:
            flush()
        case <-t.closed:
            flush()
            return
        }
    }
}
