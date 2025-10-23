//  tcp_conn.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Implements the Swift-facing TCP connection wrapper used by the bridge.

package bridge

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type swiftTCPConn struct {
	handle int64
	engine *Engine

	remote net.Addr

	mu        sync.Mutex
	recvQueue chan packetBuffer
	current   packetBuffer
	offset    int
	closed    bool
	closeErr  error
}

func newSwiftTCPConn(handle int64, metadata *M.Metadata, engine *Engine) *swiftTCPConn {
	addr := metadata.TCPAddr()
	var remote net.Addr = addr
	if remote == nil {
		remote = &net.TCPAddr{
			IP:   net.ParseIP(metadata.DstIP.String()),
			Port: int(metadata.DstPort),
		}
	}
	return &swiftTCPConn{
		handle:    handle,
		engine:    engine,
		remote:    remote,
		recvQueue: make(chan packetBuffer, 128),
	}
}

func (c *swiftTCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.mu.Lock()
	if len(c.current.buf) > 0 {
		n := copy(p, c.current.buf[c.offset:])
		c.offset += n
		if c.offset >= len(c.current.buf) {
			c.current.release()
			c.current = packetBuffer{}
			c.offset = 0
		}
		c.mu.Unlock()
		return n, nil
	}
	if c.closed {
		err := c.closeErr
		if err == nil {
			err = io.EOF
		}
		c.mu.Unlock()
		return 0, err
	}
	c.mu.Unlock()

	payload, ok := <-c.recvQueue
	if !ok {
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}

	n := copy(p, payload.buf)
	if n < len(payload.buf) {
		c.mu.Lock()
		c.current = payload
		c.offset = n
		c.mu.Unlock()
		return n, nil
	}
	payload.release()
	return n, nil
}

func (c *swiftTCPConn) Write(p []byte) (int, error) {
	if c.isClosed() {
		return 0, errors.New("connection closed")
	}
	n, err := c.engine.network.TCPWrite(c.handle, p)
	return int(n), err
}

func (c *swiftTCPConn) Close() error {
	if c.markClosed(nil) {
		c.engine.unregisterTCP(c.handle)
		return c.engine.network.TCPClose(c.handle)
	}
	return nil
}

func (c *swiftTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *swiftTCPConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *swiftTCPConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *swiftTCPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *swiftTCPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *swiftTCPConn) enqueue(payload []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.recvQueue <- adoptPacketBuffer(payload, 0)
}

func (c *swiftTCPConn) closeWithError(err error) {
	if c.markClosed(err) {
		close(c.recvQueue)
	}
}

func (c *swiftTCPConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *swiftTCPConn) markClosed(err error) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.closed = true
	c.closeErr = err
	if len(c.current.buf) > 0 {
		c.current.release()
		c.current = packetBuffer{}
		c.offset = 0
	}
	return true
}
