//  Config.go
//  RelativeProtocol Bridge
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/19/2025.
//
//  Defines the minimal configuration and interface surface exposed to the
//  gomobile bindings so Swift can exchange packets with the Go core.

package bridge

// Config captures the runtime options surfaced to the Swift layer.
type Config struct {
	// MTU is the maximum transmission unit applied to the virtual interface.
	MTU int
}

// PacketEmitter is implemented by Swift code to reflect outbound packets back
// into the Network Extension packet flow.
type PacketEmitter interface {
	EmitPacket(packet []byte, protocolNumber int32) error
}

// Network abstracts the Network Extension plumbing behind TCP and UDP sessions.
// Each method is bridged into Swift via gomobile.
type Network interface {
	// TCPDial establishes a TCP session to the destination host/port and
	// returns an opaque handle understood by Swift.
	TCPDial(host string, port int32, timeoutMillis int64) (int64, error)
	// TCPWrite writes payload bytes to the connection identified by handle.
	TCPWrite(handle int64, payload []byte) (int32, error)
	// TCPClose tears down the connection identified by handle.
	TCPClose(handle int64) error

	// UDPDial establishes a UDP session to the destination host/port and
	// returns an opaque handle understood by Swift.
	UDPDial(host string, port int32) (int64, error)
	// UDPWrite writes payload bytes to the session identified by handle.
	UDPWrite(handle int64, payload []byte) (int32, error)
	// UDPClose tears down the session identified by handle.
	UDPClose(handle int64) error
}
