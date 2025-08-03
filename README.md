# RelativeVPN

A high-performance, privacy-focused VPN implementation for iOS devices, built in C with comprehensive testing and enterprise-grade reliability.

## Features

### Core Functionality
- **Packet I/O Adapter**: Direct integration with iOS `utun` interface for raw IPv4/IPv6 frame processing
- **Lightweight TCP/UDP Engine**: lwIP-based userspace networking stack for connection management
- **Socket Bridge**: Seamless connection bridging with `createTCPConnection`/`createUDPSession` APIs
- **DNS Resolver**: On-device DNS resolution with intelligent caching for IPv4/IPv6

### Advanced Capabilities
- **Flow Metrics**: Real-time 5-tuple tracking with lock-free ring buffer for high-throughput environments
- **Dual-Stack Support**: Full IPv4/IPv6 support with NAT64 translation for cellular networks
- **MTU Discovery**: Automatic MSS clamping to prevent fragmentation issues
- **Reachability Monitoring**: Intelligent pause/resume during Wi-Fi ⇄ 5G transitions
- **Traffic Classification**: TLS/QUIC first-packet analysis for encrypted traffic tagging

### Privacy & Security
- **Zero-Logging**: Compile-time configurable logging with privacy-first defaults
- **DNS Leak Protection**: Built-in kill switch to prevent DNS leakage
- **Memory Safety**: Comprehensive AddressSanitizer integration and fuzzing harness

### iOS Integration
- **Swift Bridging**: Clean C API designed for seamless Swift integration
- **XCFramework**: Production-ready framework distribution
- **Battery Optimization**: Efficient power usage with comprehensive energy regression testing
- **Network Extension**: Full NetworkExtension framework compatibility

## Quick Start

### Prerequisites
- Xcode 14.0+
- iOS 12.0+ deployment target
- CMake 3.20+
- Network Extension entitlements

### Building

#### Standard Build
```bash
./scripts/build_ios.sh
```

#### Development Build with Tests
```bash
./scripts/build_ios.sh --debug --tests --logging
```

#### Production XCFramework
```bash
./scripts/build_ios.sh --xcframework
```

#### Fuzzing & Security Testing
```bash
./scripts/build_ios.sh --fuzzing --asan
```

### Integration

#### Swift Usage
```swift
import RelativeVPN

let config = vpn_config_t(
    utun_name: nil,
    mtu: 1500,
    ipv4_enabled: true,
    ipv6_enabled: true,
    nat64_enabled: false,
    dns_leak_protection: true,
    dns_cache_size: 1024,
    metrics_buffer_size: 4096,
    reachability_monitoring: true,
    log_level: nil
)

let result = vpn_start(&config)
guard result == VPN_SUCCESS else {
    print("VPN start failed: \\(String(cString: vpn_error_string(result)))")
    return
}

// VPN is now running
print("VPN started successfully")
```

#### Metrics Monitoring
```swift
vpn_set_metrics_callback({ metrics, userData in
    print("Bytes in: \\(metrics.pointee.bytes_in)")
    print("Bytes out: \\(metrics.pointee.bytes_out)")
    print("Active TCP connections: \\(metrics.pointee.tcp_connections)")
}, nil)
```

## Architecture

### Project Structure
```
├── src/                    # Core implementation
│   ├── api/               # Public C API
│   ├── core/              # Logging, types, utilities
│   ├── packet/            # utun interface handling
│   ├── tcp_udp/           # lwIP integration
│   ├── socket_bridge/     # Connection bridging
│   ├── dns/               # DNS resolution & caching
│   ├── metrics/           # Performance monitoring
│   ├── nat64/             # IPv6-to-IPv4 translation
│   ├── mtu/               # Path MTU discovery
│   ├── reachability/      # Network state monitoring
│   ├── classifier/        # Traffic analysis
│   └── privacy/           # Security & privacy guards
├── include/               # Public headers
├── tests/                 # Comprehensive test suite
│   ├── unit/             # Unit tests (GoogleTest)
│   ├── integration/      # Integration tests
│   ├── fuzz/             # Fuzzing harnesses
│   └── performance/      # Performance benchmarks
├── third_party/          # External dependencies
├── scripts/              # Build & utility scripts
└── cmake/                # CMake modules
```

### Performance Characteristics

#### Memory Usage
- **Static Library**: ~500KB (release build)
- **Runtime Memory**: <2MB typical usage
- **DNS Cache**: Configurable (default 1024 entries)
- **Metrics Buffer**: Lock-free ring buffer (default 4096 entries)

#### Throughput
- **Packet Processing**: >100,000 packets/second on modern iOS devices
- **Latency Overhead**: <1ms additional latency
- **Battery Impact**: <2% additional drain during active use

## Testing

### Unit Tests
```bash
# Run all unit tests
cmake --build build --target test

# Run specific test suite
./build/tests/unit_tests --gtest_filter="RingBufferTest.*"
```

### Integration Tests
```bash
# Full integration test suite
./build/tests/integration_tests

# Performance benchmarks
./build/tests/performance_tests
```

### Fuzzing
```bash
# Build fuzzing targets
./scripts/build_ios.sh --fuzzing

# Run packet parser fuzzer
./build/tests/fuzz_packet_parser
```

### Real-World Testing
```bash
# Run integration workloads
./scripts/run_integration_tests.sh --workload tiktok
./scripts/run_integration_tests.sh --workload youtube
```

## Configuration

### Compile-Time Options
- `ENABLE_LOGGING`: Debug logging (default: OFF in release)
- `ENABLE_ASAN`: AddressSanitizer (default: OFF)
- `BUILD_STATIC`: Static library build (default: ON)
- `BUILD_XCFRAMEWORK`: XCFramework generation (default: OFF)

### Runtime Configuration
```c
typedef struct vpn_config {
    char *utun_name;              // Interface name (NULL for auto)
    uint16_t mtu;                 // Maximum transmission unit
    bool ipv4_enabled;            // IPv4 support
    bool ipv6_enabled;            // IPv6 support
    bool nat64_enabled;           // NAT64 translation
    bool dns_leak_protection;     // DNS leak prevention
    uint32_t dns_cache_size;      // DNS cache entries
    uint32_t metrics_buffer_size; // Metrics ring buffer size
    bool reachability_monitoring; // Network transition handling
    char *log_level;             // Logging verbosity
} vpn_config_t;
```

## Security Considerations

### Privacy Protection
- **Zero-Logging Default**: No sensitive data logged by default
- **DNS Leak Prevention**: Automatic DNS leak detection and prevention
- **Memory Scrubbing**: Sensitive data cleared from memory after use

### Attack Surface Mitigation
- **Input Validation**: Comprehensive packet validation
- **Buffer Overflow Protection**: AddressSanitizer integration
- **Fuzzing Coverage**: Extensive fuzzing of packet parsers
- **Privilege Separation**: Minimal privilege requirements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Ensure all tests pass
5. Submit a pull request

### Development Guidelines
- Follow C11 standard
- Maintain thread safety
- Add unit tests for all new functionality
- Update documentation
- Run fuzzing tests for security-critical code

## Support

For issues, questions, or contributions, please visit our [GitHub repository](https://github.com/your-org/relative-vpn).