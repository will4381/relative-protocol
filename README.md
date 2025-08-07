# RelativeProtocol

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A clean, production-ready VPN implementation designed exclusively for iOS devices using NetworkExtension framework. Built with verified, working modules - no fake implementations or placeholders.

## ✨ Clean Architecture (Post-Audit)

After comprehensive module audit and cleanup, RelativeProtocol now contains **only working, verified implementations**:

### 🔧 Production-Ready Modules
- ✅ **Packet Buffer Manager** - Thread-safe memory management with reference counting
- ✅ **DNS Resolver** - Real UDP networking with actual query/response handling  
- ✅ **NAT64 Translator** - Full RFC 6052 IPv4/IPv6 translation with checksum adjustment
- ✅ **Connection Manager** - Comprehensive TCP/UDP tracking with atomic operations
- ✅ **Tunnel Provider** - Complete iOS NetworkExtension integration
- ✅ **iOS VPN Module** - Main packet processing and connection handling

### 🗑️ Removed Fake Implementations
- ❌ Privacy guards (blocking everything)
- ❌ Crash reporter (placeholder returns)
- ❌ Traffic classifier (empty implementations) 
- ❌ MTU discovery (fake measurements)
- ❌ Reachability monitor (no actual monitoring)

## Features

### Core VPN Functionality
- **Real Packet Processing**: Actual IPv4/IPv6 packet parsing and validation
- **Connection Tracking**: Working TCP/UDP flow management with timeouts
- **DNS Resolution**: Functional DNS queries via `sendto()/recvfrom()` 
- **Memory Management**: Proper buffer pools with mutex protection and cleanup

### iOS NetworkExtension Integration  
- **NEPacketTunnelProvider**: Native packet reading/writing via `readPacketsWithCompletionHandler`
- **Connection Creation**: Real `createTCPConnection`/`createUDPSession` calls
- **Flow Management**: Comprehensive packet flow handling with queue management
- **Thread Safety**: Proper GCD integration and mutex locking

### IPv6 & NAT64 Support
- **Dual-Stack**: Full IPv4/IPv6 packet processing 
- **NAT64 Translation**: RFC 6052 compliant address synthesis and packet translation
- **Connection Mapping**: State tracking for bidirectional flows
- **Checksum Adjustment**: Proper checksum recalculation for translated packets

## Quick Start

### Swift Package Manager Integration

```swift
dependencies: [
    .package(url: "path/to/RelativeProtocol", from: "1.0.0")
]
```

### Basic VPN Setup

```swift
import RelativeProtocol
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?) async throws {
        // Initialize VPN
        ios_vpn_init()
        
        // Process packets manually
        packetFlow.readPacketsWithCompletionHandler { packets, protocols in
            for (packet, protocolFamily) in zip(packets, protocols) {
                var info = packet_info_t()
                if ios_vpn_parse_packet(packet.bytes, packet.length, &info) {
                    // Process packet...
                }
            }
        }
    }
}
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                iOS App Layer                    │
├─────────────────────────────────────────────────┤
│            Swift Package Manager               │
│         RelativeProtocol.xcframework           │
├─────────────────────────────────────────────────┤
│  ios_vpn.c (Main packet processing)           │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌──────────────┐ ┌──────────┐ │
│  │Buffer Mgr   │ │DNS Resolver  │ │NAT64     │ │
│  │(Memory)     │ │(UDP queries) │ │(v4↔v6)   │ │
│  └─────────────┘ └──────────────┘ └──────────┘ │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌──────────────┐            │
│  │Connection   │ │Tunnel        │             │
│  │Manager      │ │Provider      │             │
│  │(TCP/UDP)    │ │(iOS Native)  │             │
│  └─────────────┘ └──────────────┘             │
├─────────────────────────────────────────────────┤
│          iOS NetworkExtension                   │
└─────────────────────────────────────────────────┘
```

## Testing

Comprehensive test suite for all working modules:

```bash
cd tests/ios
make test
```

Individual module testing:
```bash
make test-buffer      # Buffer manager tests
make test-dns         # DNS resolver tests (includes network I/O)
make test-nat64       # NAT64 translator tests
make test-vpn         # iOS VPN module tests
make test-connection  # Connection manager tests
```

## Build System

Dual build system support:

### CMake (Development)
```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make
```

### Swift Package Manager (Distribution)
```bash
swift build
swift test
```

## Project Structure

```
RelativeProtocol/
├── src/                    # Core implementation
│   ├── ios_vpn.c          # Main VPN module
│   ├── packet/            # Buffer & tunnel management
│   ├── dns/               # DNS resolution 
│   ├── nat64/             # IPv6 translation
│   ├── tcp_udp/           # Connection tracking
│   └── core/              # Logging & utilities
├── include/               # Public headers
├── tests/ios/             # Verified test suite
├── examples/              # Swift integration examples
└── RelativeProtocol.xcframework/  # iOS distribution
```

## Contributing

1. All new modules must include comprehensive tests
2. No fake implementations or placeholder returns
3. Thread safety required for all shared state
4. iOS NetworkExtension compatibility mandatory

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) for details.

---

**Production-Ready**: All included modules have been thoroughly audited and verified to contain actual working implementations.