//  udp_conn.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Implements the Swift-facing UDP session wrapper used by the bridge.

package bridge

import (
	"errors"
	"net"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type swiftUDPSession struct {
	handle int64
	engine *Engine

	remote net.Addr

	mu        sync.Mutex
	recvQueue chan []byte
	closed    bool
}

func newSwiftUDPSession(handle int64, metadata *M.Metadata, engine *Engine) *swiftUDPSession {
	addr := metadata.UDPAddr()
	var remote net.Addr = addr
	if remote == nil {
		remote = &net.UDPAddr{
			IP:   net.ParseIP(metadata.DstIP.String()),
			Port: int(metadata.DstPort),
		}
	}
	return &swiftUDPSession{
		handle:    handle,
		engine:    engine,
		remote:    remote,
		recvQueue: make(chan []byte, 64),
	}
}

func (s *swiftUDPSession) ReadFrom(p []byte) (int, net.Addr, error) {
	payload, ok := <-s.recvQueue
	if !ok {
		return 0, s.remote, errors.New("udp session closed")
	}
	n := copy(p, payload)
	return n, s.remote, nil
}

func (s *swiftUDPSession) WriteTo(p []byte, addr net.Addr) (int, error) {
	_ = addr
	if s.isClosed() {
		return 0, errors.New("udp session closed")
	}
	n, err := s.engine.network.UDPWrite(s.handle, p)
	return int(n), err
}

func (s *swiftUDPSession) Close() error {
	if s.markClosed() {
		s.engine.unregisterUDP(s.handle)
		return s.engine.network.UDPClose(s.handle)
	}
	return nil
}

func (s *swiftUDPSession) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (s *swiftUDPSession) SetDeadline(time.Time) error {
	return nil
}

func (s *swiftUDPSession) SetReadDeadline(time.Time) error {
	return nil
}

func (s *swiftUDPSession) SetWriteDeadline(time.Time) error {
	return nil
}

func (s *swiftUDPSession) enqueue(payload []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.recvQueue <- append([]byte(nil), payload...)
}

func (s *swiftUDPSession) close() {
	if s.markClosed() {
		s.engine.unregisterUDP(s.handle)
		close(s.recvQueue)
	}
}

func (s *swiftUDPSession) markClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closed = true
	return true
}

func (s *swiftUDPSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
