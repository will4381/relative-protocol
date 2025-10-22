package bridge

import (
	"errors"
)

type tunIO struct {
	emitter PacketEmitter

	inbound chan []byte
	closed  chan struct{}
}

func newTunIO(emitter PacketEmitter) *tunIO {
	return &tunIO{
		emitter: emitter,
		inbound: make(chan []byte, 512),
		closed:  make(chan struct{}),
	}
}

func (t *tunIO) Read(p []byte) (int, error) {
	select {
	case packet, ok := <-t.inbound:
		if !ok {
			return 0, errors.New("tun closed")
		}
		if len(packet) > len(p) {
			copy(p, packet[:len(p)])
			return len(p), nil
		}
		copy(p, packet)
		return len(packet), nil
	case <-t.closed:
		return 0, errors.New("tun closed")
	}
}

func (t *tunIO) Write(p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	if err := t.emitter.EmitPacket(packet, inferProtocol(packet)); err != nil {
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
	case t.inbound <- append([]byte(nil), packet...):
		return nil
	}
}
