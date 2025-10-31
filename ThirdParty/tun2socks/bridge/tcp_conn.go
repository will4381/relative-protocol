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
	recvQueue chan pooledBytes
	buffer    []byte
	closed    bool
	closeErr  error
}

const tcpRecvQueueDepth = 16

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
		recvQueue: make(chan pooledBytes, tcpRecvQueueDepth),
	}
}

func (c *swiftTCPConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buffer) > 0 {
		n := copy(p, c.buffer)
		c.buffer = c.buffer[n:]
		c.mu.Unlock()
		return n, nil
	}
	if c.closed && len(c.buffer) == 0 {
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
	defer payload.release()

	data := payload.bytes()
	n := copy(p, data)
	if n < len(data) {
		c.mu.Lock()
		c.buffer = append(c.buffer, data[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

func (c *swiftTCPConn) Write(p []byte) (int, error) {
	if c.isClosed() {
		return 0, errors.New("connection closed")
	}
	c.engine.touchActivity()
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
	c.recvQueue <- newPooledBytes(payload)
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
	return true
}
