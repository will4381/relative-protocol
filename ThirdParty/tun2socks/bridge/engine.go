//  Engine.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Wires the Go tun2socks core to the Swift-based Network Extension host,
//  translating callbacks and connection lifecycles between the two runtimes.

package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
)

const (
	afInet  = 2  // AF_INET
	afInet6 = 30 // AF_INET6
)

// Engine wires the Go tun2socks core to the Swift-based Network Extension host.
type Engine struct {
	cfg Config

	packetEmitter PacketEmitter
	network       Network

	tun     *tunIO
	device  device.Device
	stack   *stack.Stack
	tunnel  *tunnel.Tunnel
	closing chan struct{}

	mu      sync.Mutex
	running bool
	runFlag atomic.Bool

	tcpConns map[int64]*swiftTCPConn
	udpConns map[int64]*swiftUDPSession
}

// NewEngine constructs a new bridge instance.
func NewEngine(cfg *Config, emitter PacketEmitter, network Network) (*Engine, error) {
	if emitter == nil {
		return nil, errors.New("packet emitter is required")
	}
	if network == nil {
		return nil, errors.New("network adapter is required")
	}
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}

	copyCfg := *cfg
	return &Engine{
		cfg:           copyCfg,
		packetEmitter: emitter,
		network:       network,
		closing:       make(chan struct{}),
		tcpConns:      make(map[int64]*swiftTCPConn),
		udpConns:      make(map[int64]*swiftUDPSession),
	}, nil
}

// Start boots the underlying gVisor stack and begins processing flows.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}

	tunRW := newTunIO(e.packetEmitter)

	endpoint, err := iobased.New(tunRW, uint32(e.cfg.MTU), 0)
	if err != nil {
		return fmt.Errorf("create tun endpoint: %w", err)
	}

	e.tun = tunRW
	e.device = &ioDevice{
		Endpoint: endpoint,
		mtu:      uint32(e.cfg.MTU),
	}

	e.tunnel = tunnel.New(&swiftDialer{engine: e}, statistic.DefaultManager)
	e.tunnel.ProcessAsync()

	e.stack, err = core.CreateStack(&core.Config{
		LinkEndpoint:     e.device,
		TransportHandler: e.tunnel,
		Options:          nil,
	})
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}

	go func() {
		<-e.closing
		endpoint.Wait()
	}()

	e.running = true
	e.runFlag.Store(true)
	return nil
}

// Stop tears the bridge down and releases resources.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	e.runFlag.Store(false)
	close(e.closing)
	e.mu.Unlock()

	e.tunnel.Close()
	e.tun.Close()

	e.mu.Lock()
	for handle, conn := range e.tcpConns {
		conn.closeWithError(errors.New("engine stopped"))
		delete(e.tcpConns, handle)
	}
	for handle, sess := range e.udpConns {
		sess.close()
		delete(e.udpConns, handle)
	}
	e.mu.Unlock()
}

// HandlePacket injects an inbound packet (read from packetFlow) into the Go stack.
func (e *Engine) HandlePacket(packet []byte, protocolNumber int32) error {
	if !e.IsRunning() {
		return errors.New("engine not running")
	}
	return e.tun.Inject(packet, protocolNumber)
}

// IsRunning reports whether Start has been called successfully.
func (e *Engine) IsRunning() bool {
	return e.runFlag.Load()
}

// TCPDidReceive delivers data produced by Swift for a given TCP handle.
func (e *Engine) TCPDidReceive(handle int64, payload []byte) {
	e.mu.Lock()
	conn := e.tcpConns[handle]
	e.mu.Unlock()
	if conn == nil {
		return
	}
	conn.enqueue(payload)
}

// TCPDidClose notifies the Go side that Swift has closed a TCP connection.
func (e *Engine) TCPDidClose(handle int64, message string) {
	e.mu.Lock()
	conn := e.tcpConns[handle]
	delete(e.tcpConns, handle)
	e.mu.Unlock()
	if conn == nil {
		return
	}
	var err error
	if message != "" {
		err = errors.New(message)
	}
	conn.closeWithError(err)
}

// UDPDidReceive delivers a UDP datagram produced by Swift.
func (e *Engine) UDPDidReceive(handle int64, payload []byte) {
	e.mu.Lock()
	session := e.udpConns[handle]
	e.mu.Unlock()
	if session == nil {
		return
	}
	session.enqueue(payload)
}

// UDPDidClose tears down the UDP session identified by handle.
func (e *Engine) UDPDidClose(handle int64, message string) {
	e.mu.Lock()
	session := e.udpConns[handle]
	delete(e.udpConns, handle)
	e.mu.Unlock()
	if session == nil {
		return
	}
	session.close()
}

func (e *Engine) registerTCP(handle int64, conn *swiftTCPConn) {
	e.mu.Lock()
	e.tcpConns[handle] = conn
	e.mu.Unlock()
}

func (e *Engine) unregisterTCP(handle int64) {
	e.mu.Lock()
	delete(e.tcpConns, handle)
	e.mu.Unlock()
}

func (e *Engine) registerUDP(handle int64, sess *swiftUDPSession) {
	e.mu.Lock()
	e.udpConns[handle] = sess
	e.mu.Unlock()
}

func (e *Engine) unregisterUDP(handle int64) {
	e.mu.Lock()
	delete(e.udpConns, handle)
	e.mu.Unlock()
}

type ioDevice struct {
	*iobased.Endpoint
	mtu uint32
}

func (d *ioDevice) Name() string {
	return "bridge0"
}

func (d *ioDevice) Type() string {
	return "iobased"
}

func (d *ioDevice) Close() {
	d.Endpoint.Close()
}

func inferProtocol(payload []byte) int32 {
	if len(payload) == 0 {
		return afInet
	}
	switch header.IPVersion(payload) {
	case header.IPv6Version:
		return afInet6
	default:
		return afInet
	}
}

type swiftDialer struct {
	engine *Engine
}

func (d *swiftDialer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	host := metadata.DstIP.String()
	port := int32(metadata.DstPort)
	timeout := contextDeadlineMillis(ctx)

	handle, err := d.engine.network.TCPDial(host, port, timeout)
	if err != nil {
		return nil, err
	}

	conn := newSwiftTCPConn(handle, metadata, d.engine)
	d.engine.registerTCP(handle, conn)
	return conn, nil
}

func (d *swiftDialer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	host := metadata.DstIP.String()
	port := int32(metadata.DstPort)

	handle, err := d.engine.network.UDPDial(host, port)
	if err != nil {
		return nil, err
	}

	session := newSwiftUDPSession(handle, metadata, d.engine)
	d.engine.registerUDP(handle, session)
	return session, nil
}

func contextDeadlineMillis(ctx context.Context) int64 {
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout < 0 {
			return 0
		}
		return timeout.Milliseconds()
	}
	return 0
}
