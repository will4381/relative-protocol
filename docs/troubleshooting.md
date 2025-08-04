# Troubleshooting Guide

Common issues and solutions when integrating RelativeProtocol into your iOS app.

## iOS Version Specific Issues

### iOS 17+ Privacy Requirements

**Error:**
```
App Store Connect: Missing Privacy Manifest
```

**Solution:**
Add `PrivacyInfo.xcprivacy` to your project:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryNetworking</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>NSPrivacyAccessedAPITypeReasonNetworkProtocolStack</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

### iOS 18+ Enhanced App Privacy

**Issue:** NetworkExtension permission prompts changed in iOS 18

**Solution:**
Update your permission request flow:
```swift
// iOS 18+ requires explicit user education before VPN permission
func requestVPNPermission() async {
    // Show educational UI first
    await showVPNEducationScreen()
    
    // Then request permission
    try await vpnManager.saveToPreferences()
}
```

## Build Errors

### "unsigned framework" error

**Error:**
```
The operation couldn't be completed. Unable to launch because it has an invalid code signature, inadequate entitlements or its profile has not been explicitly trusted by the user.
```

**Solution:**
Sign the XCFramework with an ad-hoc signature:
```bash
codesign --sign - --deep RelativeProtocol.xcframework
```

### "file not found" in bridging header

**Error:**
```
'RelativeProtocol/RelativeProtocol.h' file not found
```

**Solutions:**

1. **Don't use a bridging header** for Swift Package Manager binary frameworks:
   ```swift
   // Just import directly in Swift
   import RelativeProtocol
   ```

2. **If you must use a bridging header**, ensure the framework is properly linked:
   - Select your target → General → Frameworks and Libraries
   - Add RelativeProtocol.xcframework
   - Set to "Do Not Embed" for extensions

### "no library for this platform was found"

**Error:**
```
While building for macOS, no library for this platform was found in 'RelativeProtocol.xcframework'
```

**Solution:**
The framework only supports iOS. Ensure your target platform is set to iOS, not macOS.

**For Mac Catalyst:**
The framework doesn't support Mac Catalyst. If you need Mac support, build a separate macOS version or exclude VPN functionality on Mac.

### Swift Package Manager Binary Target Issues

**Error:**
```
failed to extract archive: The file "RelativeProtocol.xcframework" couldn't be opened
```

**Solutions:**
1. **Verify XCFramework integrity:**
   ```bash
   xcodebuild -checkFirstLaunchStatus
   file RelativeProtocol.xcframework/Info.plist
   ```

2. **Check git LFS if using large files:**
   ```bash
   git lfs track "*.xcframework"
   git add .gitattributes
   ```

3. **Ensure proper Package.swift configuration:**
   ```swift
   .binaryTarget(
       name: "RelativeProtocol",
       url: "https://github.com/user/repo/releases/download/v1.0.0/RelativeProtocol.xcframework.zip",
       checksum: "sha256-checksum-here"
   )
   ```

### "expected library was not found"

**Error:**
```
When building for iOS, the expected library .../RelativeProtocol.xcframework/ios-arm64/librelative_vpn-arm64.a was not found
```

**Solutions:**

1. **Update to latest package version:**
   - File → Packages → Update to Latest Package Versions
   
2. **Reset package cache:**
   - File → Packages → Reset Package Caches
   
3. **Ensure binaries are in git:**
   - Check that `.gitignore` allows XCFramework binaries:
   ```
   !RelativeProtocol.xcframework/**/*.a
   ```

## Runtime Errors

### VPN Won't Connect

**Checklist:**

1. **NetworkExtension entitlement:**
   ```xml
   <key>com.apple.developer.networking.networkextension</key>
   <array>
       <string>packet-tunnel-provider</string>
   </array>
   ```

2. **Info.plist configuration:**
   ```xml
   <key>NSExtension</key>
   <dict>
       <key>NSExtensionPointIdentifier</key>
       <string>com.apple.networkextension.packet-tunnel</string>
       <key>NSExtensionPrincipalClass</key>
       <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
   </dict>
   ```

3. **Check logs:**
   ```swift
   log_set_level(LOG_LEVEL_DEBUG)
   log_set_handler { level, message in
       print("[VPN][\(level)] \(String(cString: message))")
   }
   ```

### Memory Leaks

**Common causes:**

1. **Not calling destroy:**
   ```swift
   // Bad
   let vpn = relative_vpn_create(&config)
   // Missing: relative_vpn_destroy(vpn)
   
   // Good
   defer {
       if let vpn = vpnInstance {
           relative_vpn_destroy(vpn)
       }
   }
   ```

2. **Retained bridge objects:**
   ```swift
   // Ensure proper memory management for bridged objects
   autoreleasepool {
       // Your NetworkExtension code here
   }
   ```

### Connection Drops

**Debug steps:**

1. **Check metrics:**
   ```swift
   var metrics = vpn_metrics_t()
   relative_vpn_get_metrics(vpn, &metrics)
   print("Last error: \(metrics.last_error_code)")
   print("Reconnect count: \(metrics.reconnect_count)")
   ```

2. **Monitor network changes:**
   ```swift
   let monitor = NWPathMonitor()
   monitor.pathUpdateHandler = { path in
       if path.status != .satisfied {
           // Handle network loss
       }
   }
   ```

3. **Check privacy violations:**
   ```swift
   let violations = relative_vpn_get_privacy_violations_count(vpn)
   if violations > 0 {
       // Investigate privacy issues
   }
   ```

## Integration Issues

### Swift Package Manager

**Issue:** Package not showing up in Xcode

**Solutions:**
1. Ensure you're using the correct URL
2. Check that you've pushed all commits including the XCFramework
3. Try adding with a specific branch or tag:
   ```
   https://github.com/user/repo.git
   Branch: main
   ```

**Issue:** Binary target not found

**Solution:**
Ensure Package.swift has correct path:
```swift
.binaryTarget(
    name: "RelativeProtocol",
    path: "RelativeProtocol.xcframework"  // Must match actual path
)
```

### Xcode Project Configuration

**Issue:** Extension crashes on launch

**Common causes:**
1. Missing entitlements
2. Incorrect bundle identifier
3. Framework not embedded correctly

**Debug:**
```bash
# Check entitlements
codesign -d --entitlements - YourApp.app
codesign -d --entitlements - YourApp.app/PlugIns/YourExtension.appex

# Check frameworks
otool -L YourApp.app/PlugIns/YourExtension.appex/YourExtension
```

## Performance Issues

### High CPU Usage

**Optimize packet processing:**
```swift
// Use buffer pools
let bufferManager = buffer_manager_create(100)
defer { buffer_manager_destroy(bufferManager) }

// Process packets efficiently
let buffer = buffer_manager_allocate(bufferManager, packetSize)
defer { buffer_manager_release(bufferManager, buffer) }
```

### Memory Usage

**Monitor and limit:**
```swift
// Set reasonable limits
var config = vpn_config_t()
config.dns_cache_size = 500  // Instead of default 1000
config.metrics_buffer_size = 50  // Instead of default 100
```

## Debug Techniques

### Enable Verbose Logging

```swift
// Modern logging with os_log (iOS 15+)
import os.log

override func startTunnel(...) {
    // Create logger with subsystem
    let logger = Logger(subsystem: "com.yourcompany.vpn", category: "network")
    
    // Enable debug logging
    log_set_level(LOG_LEVEL_DEBUG)
    
    // Custom handler using modern Logger
    log_set_handler { level, message in
        let logLevel: OSLogType = switch level {
        case LOG_LEVEL_ERROR: .error
        case LOG_LEVEL_WARN: .default
        case LOG_LEVEL_INFO: .info
        case LOG_LEVEL_DEBUG: .debug
        default: .default
        }
        
        logger.log(level: logLevel, "\(String(cString: message), privacy: .public)")
    }
}
```

**Console filtering (iOS 15+):**
```bash
# Filter logs by subsystem
log stream --predicate 'subsystem == "com.yourcompany.vpn"' --level debug

# Filter by process
log stream --predicate 'process == "YourApp"' --style syslog
```
```

### Packet Inspection

```swift
// Log packet details
func logPacket(_ packet: packet_t) {
    let ipVersion = packet.protocol_family == AF_INET ? "IPv4" : "IPv6"
    print("Packet: \(ipVersion), \(packet.length) bytes")
    
    // Check if encrypted
    if classifier_is_tls(packet.data, packet.length) {
        print("Protocol: TLS")
    } else if classifier_is_quic(packet.data, packet.length) {
        print("Protocol: QUIC")
    }
}
```

### Network Extension Debugging

1. **Attach to Network Extension:**
   - Debug → Attach to Process by PID or Name
   - Enter your extension's bundle ID

2. **Console logs:**
   ```bash
   # Stream logs from device (iOS 15+)
   xcrun simctl spawn booted log stream --level debug --predicate 'subsystem == "com.yourcompany.app.tunnel"'
   
   # For physical devices
   log stream --device-name "iPhone" --predicate 'subsystem == "com.yourcompany.app.tunnel"'
   ```

3. **Crash logs:**
   - Window → Devices and Simulators
   - View Device Logs
   - For iOS 17+: Console.app → Device → Crash Reports

4. **Network Extension specific debugging:**
   ```bash
   # Monitor NetworkExtension logs specifically
   log stream --predicate 'subsystem CONTAINS "NetworkExtension"' --level debug
   
   # Monitor your extension specifically
   log stream --predicate 'process == "com.yourcompany.app.tunnel"' --level debug
   ```

5. **iOS 18+ Privacy debugging:**
   ```swift
   // Check network privacy status
   func checkNetworkPrivacyStatus() {
       // Monitor network changes
       let monitor = NWPathMonitor()
       monitor.pathUpdateHandler = { path in
           print("Network path: \(path)")
           print("Expensive: \(path.isExpensive)")
           print("Constrained: \(path.isConstrained)")
       }
   }
   ```

## Common Error Codes

| Code | Constant | Description | Solution |
|------|----------|-------------|----------|
| 0 | VPN_SUCCESS | Success | N/A |
| -1 | VPN_ERROR_INVALID_CONFIG | Invalid configuration | Check server address, port |
| -2 | VPN_ERROR_CONNECTION_FAILED | Connection failed | Check network, server |
| -3 | VPN_ERROR_AUTH_FAILED | Authentication failed | Verify auth token |
| -4 | VPN_ERROR_TIMEOUT | Connection timeout | Increase timeout, check network |
| -5 | VPN_ERROR_MEMORY | Memory allocation failed | Check memory usage |
| -6 | VPN_ERROR_NETWORK | Network error | Check connectivity |
| -7 | VPN_ERROR_NOT_CONNECTED | Not connected | Connect before operation |
| -8 | VPN_ERROR_ALREADY_CONNECTED | Already connected | Disconnect first |
| -9 | VPN_ERROR_PERMISSION_DENIED | Permission denied | Check entitlements |
| -10 | VPN_ERROR_PROTOCOL | Protocol error | Update framework |
| -11 | VPN_ERROR_SERVER_UNREACHABLE | Server unreachable | Check server status |
| -12 | VPN_ERROR_CERTIFICATE | Certificate error | Check TLS certificates |

## Getting Help

1. **Enable debug logging** and check Console.app
2. **Search existing issues** on GitHub
3. **Create minimal reproduction** case
4. **Include system info:**
   - iOS version
   - Xcode version
   - Framework version
   - Device model

When reporting issues, include:
- Full error messages
- Relevant code snippets
- Console logs with debug enabled
- Steps to reproduce