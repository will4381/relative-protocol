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
)

type tunIO struct {
	emitter PacketEmitter

	inbound chan packetBuffer
	closed  chan struct{}
}

func newTunIO(emitter PacketEmitter) *tunIO {
	return &tunIO{
		emitter: emitter,
		inbound: make(chan packetBuffer, 1024),
		closed:  make(chan struct{}),
	}
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
	buffer := newPooledPacketBuffer(len(p))
	copy(buffer.buf, p)
	buffer.proto = inferProtocol(buffer.buf)
	if err := t.emitter.EmitPacket(buffer.buf, buffer.proto); err != nil {
		buffer.release()
		return 0, err
	}
	buffer.release()
	return len(p), nil
}

func (t *tunIO) Close() {
	select {
	case <-t.closed:
		return
	default:
		close(t.closed)
		close(t.inbound)
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
