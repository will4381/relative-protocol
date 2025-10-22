package bridge

// Config captures the tun2socks runtime options surfaced to the Swift side.
type Config struct {
	// MTU is the maximum transmission unit applied to the virtual interface.
	MTU int
}

// PacketEmitter is satisfied by Swift code that reflects outbound packets back
// into the Network Extension packetFlow.
type PacketEmitter interface {
	EmitPacket(packet []byte, protocolNumber int32) error
}

// Network abstracts the Network Extension plumbing that powers TCP and UDP
// sessions. Each method is bridged into Swift via gomobile.
type Network interface {
	// TCPDial establishes a TCP session to the destination host/port and
	// returns an opaque handle understood by the Swift layer.
	TCPDial(host string, port int32, timeoutMillis int64) (int64, error)
	// TCPWrite writes payload bytes to the connection identified by handle.
	TCPWrite(handle int64, payload []byte) (int32, error)
	// TCPClose tears down the connection identified by handle.
	TCPClose(handle int64) error

	// UDPDial establishes a UDP session to the destination host/port and
	// returns an opaque handle understood by the Swift layer.
	UDPDial(host string, port int32) (int64, error)
	// UDPWrite writes payload bytes to the session identified by handle.
	UDPWrite(handle int64, payload []byte) (int32, error)
	// UDPClose tears down the session identified by handle.
	UDPClose(handle int64) error
}
