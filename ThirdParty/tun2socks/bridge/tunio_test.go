package bridge

import (
    "bytes"
    "testing"
)

type testEmitter struct {
    packets [][]byte
    protocols []int32
}

func (e *testEmitter) EmitPacket(packet []byte, protocolNumber int32) error {
    e.packets = append(e.packets, packet)
    e.protocols = append(e.protocols, protocolNumber)
    return nil
}

func (e *testEmitter) EmitPacketBatch(packed []byte, sizes []byte, protocols []byte) error {
    return nil
}

func TestTunIOWriteCopiesPacket(t *testing.T) {
    emitter := &testEmitter{}
    tun := newTunIO(emitter)

    original := []byte{0x45, 0x00, 0x00, 0x14}
    if _, err := tun.Write(original); err != nil {
        t.Fatalf("write failed: %v", err)
    }

    original[0] = 0x99

    if len(emitter.packets) != 1 {
        t.Fatalf("expected 1 emitted packet, got %d", len(emitter.packets))
    }
    if bytes.Equal(emitter.packets[0], original) {
        t.Fatalf("expected emitted packet to be a copy, but it tracked original slice")
    }
}

func TestTunIOInjectAndRead(t *testing.T) {
    emitter := &testEmitter{}
    tun := newTunIO(emitter)

    payload := []byte{0xde, 0xad, 0xbe, 0xef}
    if err := tun.Inject(payload); err != nil {
        t.Fatalf("inject failed: %v", err)
    }

    buf := make([]byte, 8)
    n, err := tun.Read(buf)
    if err != nil {
        t.Fatalf("read failed: %v", err)
    }
    if n != len(payload) {
        t.Fatalf("expected %d bytes, got %d", len(payload), n)
    }
    if !bytes.Equal(buf[:n], payload) {
        t.Fatalf("unexpected payload: %x", buf[:n])
    }
}
