# RelativeProtocol VPN - Extensive Logging Guide

This document explains how to enable extensive logging in the RelativeProtocol VPN to debug network connectivity and packet forwarding issues.

## Quick Start

```c
#include "api/relative_vpn.h"

// Set log level to maximum verbosity
vpn_set_log_level("TRACE");

// Set custom log callback to capture messages
void my_log_callback(const char *message, void *user_data) {
    printf("[VPN] %s\n", message);
}
vpn_set_log_callback(my_log_callback, NULL);

// Start VPN with logging enabled
vpn_config_t config = {0};
config.log_level = "TRACE";
vpn_start(&config);
```

## Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| **TRACE** | Maximum verbosity - every packet detail | Deep debugging packet issues |
| **DEBUG** | Packet summaries, connection tracking | General debugging |
| **INFO** | Important events, connections created/closed | Normal operation monitoring |
| **WARN** | Potential issues, recoverable errors | Production monitoring |
| **ERROR** | Actual errors, failed operations | Error tracking |
| **CRITICAL** | Critical failures | Emergency issues |
| **SILENT** | No logging | Production (quiet) |

## What Gets Logged

### TRACE Level Logging Includes:
- **Packet Reception**: Every incoming packet with full header details
- **Header Parsing**: IP version, protocol, source/destination IPs and ports
- **Payload Analysis**: TCP/UDP payload sizes and offsets
- **Buffer Management**: Buffer pool operations, memory allocation/deallocation
- **Connection Tracking**: Connection creation, lookup, and state changes
- **Packet Building**: Response packet construction with checksum calculations
- **Network Interface**: Packet forwarding to/from tunnel interface

### DEBUG Level Logging Includes:
- **Packet Summaries**: Source -> Destination (Protocol, Size)
- **Connection Events**: New connections, connection matching
- **NAT64 Translation**: IPv4 <-> IPv6 translation events
- **DNS Queries**: Hostname lookups and responses
- **Error Recovery**: Retry attempts and fallback mechanisms

### INFO Level Logging Includes:
- **Module Initialization**: VPN startup/shutdown events
- **Configuration Changes**: Log level changes, feature enabling/disabling
- **Connection Statistics**: Active connection counts
- **Performance Metrics**: Packet/byte counters

## Common Debugging Scenarios

### 1. No Internet Connectivity
```c
// Enable maximum logging
vpn_set_log_level("TRACE");

// Look for these log messages:
// - "Packet parsed successfully" (packets being received)
// - "Found matching connection" (connection tracking working)
// - "Successfully sent packet to tunnel" (forwarding working)
// - "NAT64 translating" (IPv6/IPv4 translation if enabled)
```

### 2. Packet Forwarding Issues  
```c
// Enable DEBUG logging to see packet flow
vpn_set_log_level("DEBUG");

// Key messages to look for:
// - "Processing [TCP/UDP] packet: src -> dst"
// - "Response packet built successfully"
// - "Writing packet to tunnel flow"
// - "Packet forwarding failed" or "Tunnel provider requires"
```

### 3. Connection Tracking Problems
```c
// Enable DEBUG logging
vpn_set_log_level("DEBUG");

// Monitor these messages:
// - "Created new connection" (connections being established)  
// - "Found existing connection" vs "No existing connection found"
// - "Connection [id] state: active=[true/false]"
// - "Ignoring packet for inactive/closed connection"
```

### 4. Header Reconstruction Issues
```c
// Enable TRACE logging for detailed header analysis
vpn_set_log_level("TRACE");

// Check these detailed logs:
// - "IPv4 header length: X bytes"
// - "TCP/UDP header set: src_port=X, dst_port=Y"  
// - "IP/TCP/UDP checksum calculated: 0xXXXX"
// - "IP addresses swapped: src=X, dst=Y"
```

## Example Output

When TRACE logging is enabled, you'll see output like:

```
[2024-01-15 10:30:45] TRACE ios_vpn.c:100 - Parsing packet: length=60
[2024-01-15 10:30:45] TRACE ios_vpn.c:111 - IP version: 4  
[2024-01-15 10:30:45] TRACE ios_vpn.c:120 - IPv4 header length: 20 bytes
[2024-01-15 10:30:45] TRACE ios_vpn.c:129 - Protocol: 6 (TCP)
[2024-01-15 10:30:45] TRACE ios_vpn.c:135 - Source IP: 192.168.1.2
[2024-01-15 10:30:45] TRACE ios_vpn.c:136 - Destination IP: 192.168.1.1
[2024-01-15 10:30:45] TRACE ios_vpn.c:147 - Source port: 1234
[2024-01-15 10:30:45] TRACE ios_vpn.c:148 - Destination port: 80  
[2024-01-15 10:30:45] TRACE ios_vpn.c:157 - TCP payload length: 20 bytes
[2024-01-15 10:30:45] DEBUG ios_vpn.c:180 - Packet parsed successfully: 192.168.1.2:1234 -> 192.168.1.1:80 (TCP, 60 bytes)
```

## Performance Impact

- **TRACE/DEBUG**: High overhead, use only for debugging
- **INFO**: Low overhead, suitable for production monitoring  
- **WARN/ERROR**: Minimal overhead, always safe to use
- **SILENT**: No overhead

## API Reference

```c
// Set log level (runtime changeable)
vpn_status_t vpn_set_log_level(const char *level);

// Get current log level  
vpn_status_t vpn_get_log_level(char *level, size_t level_size);

// Set custom log callback
vpn_status_t vpn_set_log_callback(vpn_log_callback_t callback, void *user_data);

// Initialize with specific log level
vpn_config_t config = {.log_level = "TRACE"};
vpn_start(&config);
```

## Test Program

Run the included test program to see logging in action:

```bash
# Build and run the logging test
gcc -I../include examples/logging_test.c src/*.c -o logging_test
./logging_test
```

This will demonstrate all logging levels and show you exactly what information is available at each level.

## Troubleshooting

If you don't see expected log output:

1. **Check log level**: Ensure you're using the right level (TRACE for maximum detail)
2. **Verify callback**: Make sure your log callback is properly set
3. **Check compilation**: Ensure `ENABLE_LOGGING` is defined during compilation  
4. **Platform support**: Some advanced features require iOS platform (`TARGET_OS_IOS`)

The extensive logging system will help you identify exactly where packets are being dropped, why connections aren't being tracked, or where header reconstruction is failing.