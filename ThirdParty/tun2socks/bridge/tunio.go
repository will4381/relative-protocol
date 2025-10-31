//  tunio.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Provides a channel-backed conduit between Swift packet emission/ingestion
//  and the Go tun device abstraction.

package bridge

import "errors"

const tunInboundDepth = 128

type tunIO struct {
	emitter PacketEmitter

	inbound chan pooledBytes
	closed  chan struct{}
}

func newTunIO(emitter PacketEmitter) *tunIO {
	return &tunIO{
		emitter: emitter,
		inbound: make(chan pooledBytes, tunInboundDepth),
		closed:  make(chan struct{}),
	}
}

func (t *tunIO) Read(p []byte) (int, error) {
	select {
	case packet, ok := <-t.inbound:
		if !ok {
			return 0, errors.New("tun closed")
		}
		defer packet.release()

		data := packet.bytes()
		if len(data) > len(p) {
			copy(p, data[:len(p)])
			return len(p), nil
		}
		copy(p, data)
		return len(data), nil
	case <-t.closed:
		return 0, errors.New("tun closed")
	}
}

func (t *tunIO) Write(p []byte) (int, error) {
	packet := newPooledBytes(p)
	defer packet.release()

	data := packet.bytes()
	if err := t.emitter.EmitPacket(data, inferProtocol(data)); err != nil {
		return 0, err
	}
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

func (t *tunIO) Inject(packet []byte) error {
	select {
	case <-t.closed:
		return errors.New("tun closed")
	case t.inbound <- newPooledBytes(packet):
		return nil
	}
}
