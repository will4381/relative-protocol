# Upload Debugging Plan

## Problem Statement
- **Download**: Working (500 Mbps on speed test)
- **Upload**: Not working at all
- **VPN otherwise functional** for browsing (which is mostly download-heavy)

## Upload Data Flow Analysis

Understanding the full path data takes for uploads:

```
App → Tunnel Interface → NEPacketTunnelProvider.packetFlow.readPackets()
    → BridgeEngineHandlePacket() → Rust smoltcp stack
    → tcp_send callback → Swift handleTcpSend()
    → SocketManager.sendTCP() → NWConnection.send()
    → Real Network
```

## Debugging Steps

### Step 1: Verify Packets Are Being Read from Tunnel
**Location**: `ProviderController.swift:130-152`

Add logging to confirm outbound packets are being read:
```swift
private func startPacketRead() {
    tunnelProvider?.packetFlow.readPackets { packets, protocols in
        // ADD: Log packet count and sizes
        os_log(.info, log: log, "[PacketRead] Received %d packets from tunnel", packets.count)
        for (i, packet) in packets.enumerated() {
            // Log direction hint from IP header if possible
        }
    }
}
```

### Step 2: Verify Rust Engine Receives Packets
**Location**: Rust engine's `BridgeEngineHandlePacket`

The Rust side should be logging when it receives packets. Check if outbound (upload) packets are being processed.

### Step 3: Verify tcp_send Callback Is Called
**Location**: `ProviderController.swift:193-195`

Add logging to `handleTcpSend`:
```swift
func handleTcpSend(handle: UInt64, data: Data) {
    os_log(.info, log: log, "[TCP_SEND] handle=%llu sending %d bytes", handle, data.count)
    Task { await socketManager.sendTCP(handle: handle, data: data) }
}
```

### Step 4: Verify NWConnection.send() Completion
**Location**: `SocketManager.swift:147-156`

The current `sendTCP` uses `.idempotent` completion which doesn't report errors. Change to proper completion handler:
```swift
func sendTCP(handle: UInt64, data: Data) async {
    guard let connection = tcpConnections[handle] else {
        os_log(.debug, log: log, "[TCP] handle=%llu sendTCP - connection already closed", handle)
        return
    }
    tcpBytesSent += UInt64(data.count)
    os_log(.info, log: log, "[TCP] handle=%llu SENDING %d bytes", handle, data.count)

    connection.send(content: data, completion: .contentProcessed { error in
        if let error = error {
            os_log(.error, log: log, "[TCP] handle=%llu send FAILED: %{public}@", handle, error.localizedDescription)
        } else {
            os_log(.debug, log: log, "[TCP] handle=%llu send completed successfully", handle)
        }
    })
}
```

### Step 5: Check TCP Flow Control / Backpressure
**Potential Issue**: If NWConnection's send buffer is full, sends may be queued or dropped.

Consider:
- Track pending sends per connection
- Implement backpressure signaling to Rust
- Check if `isReady` state is still valid when sending

### Step 6: Verify UDP Send Path (for DNS, etc.)
Same analysis for UDP since some protocols may use UDP for upload.

## Implementation Order

1. **Add logging first** - Non-invasive, helps identify where data stops flowing
2. **Fix send completion handler** - Switch from `.idempotent` to `.contentProcessed`
3. **Add send counters** - Track bytes sent vs bytes queued
4. **Review backpressure** - Ensure Rust engine can handle send failures

## Success Criteria
- Speed test shows upload working
- Logs show complete data flow from tunnel → NWConnection.send()
- No errors in send completion handlers
