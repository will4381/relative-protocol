# iOS Integration Guide for RelativeProtocol

This guide provides comprehensive instructions for integrating the RelativeProtocol VPN framework into your iOS application.

## Table of Contents
- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Basic Setup](#basic-setup)
- [API Reference](#api-reference)
- [Implementation Guide](#implementation-guide)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

RelativeProtocol is an iOS-only VPN framework built on Apple's NetworkExtension framework. It provides a high-performance, privacy-focused VPN implementation with features including:

- iOS NetworkExtension packet tunnel provider
- DNS caching and resolution
- Privacy guards and TLS validation
- Crash reporting and metrics
- NAT64 translation support
- MTU discovery
- Connection management

## Requirements

- iOS 15.0 or later (iOS 17.0+ recommended for latest privacy features)
- Xcode 15.0 or later
- Swift 5.9 or later
- NetworkExtension entitlement
- Personal VPN capability

## Installation

### Swift Package Manager

1. In Xcode, go to File → Add Package Dependencies
2. Enter the repository URL: `https://github.com/yourusername/relativeProtocol`
3. Select your desired version or branch
4. Add the package to your Network Extension target

### Manual Integration

1. Download the `RelativeProtocol.xcframework`
2. Drag it into your Xcode project
3. Add it to your Network Extension target
4. Ensure "Do Not Embed" is selected for the framework

## Basic Setup

### 1. Network Extension Configuration

First, create a Network Extension target in your project:

1. File → New → Target → Network Extension
2. Select "Packet Tunnel Provider"
3. Configure App Groups for data sharing between main app and extension
4. Configure your extension's Info.plist:

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.networkextension.packet-tunnel</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
</dict>
```

### 2. Entitlements

Add the following to your app's entitlements:

```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>packet-tunnel-provider</string>
</array>
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.yourcompany.vpn-shared</string>
</array>
```

### 3. Import the Framework

In your Swift code:

```swift
import RelativeProtocol
import NetworkExtension
```

## API Reference

### Core VPN Functions

```c
// Create VPN instance
relative_vpn_t* relative_vpn_create(vpn_config_t* config);

// Start VPN connection
vpn_error_t relative_vpn_start(relative_vpn_t* vpn);

// Stop VPN connection
vpn_error_t relative_vpn_stop(relative_vpn_t* vpn);

// Destroy VPN instance
void relative_vpn_destroy(relative_vpn_t* vpn);

// Get connection status
vpn_status_t relative_vpn_get_status(relative_vpn_t* vpn);
```

### Configuration Structure

```c
typedef struct vpn_config {
    char server_address[256];
    uint16_t server_port;
    char auth_token[512];
    uint32_t max_retries;
    uint32_t timeout_ms;
    bool enable_dns_cache;
    bool enable_privacy_guards;
} vpn_config_t;
```

### Error Codes

```c
typedef enum {
    VPN_SUCCESS = 0,
    VPN_ERROR_INVALID_CONFIG = -1,
    VPN_ERROR_CONNECTION_FAILED = -2,
    VPN_ERROR_AUTH_FAILED = -3,
    VPN_ERROR_TIMEOUT = -4,
    VPN_ERROR_MEMORY = -5,
    VPN_ERROR_NETWORK = -6
} vpn_error_t;
```

## Implementation Guide

### 1. Create Your Packet Tunnel Provider

```swift
import NetworkExtension
import RelativeProtocol

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var vpnInstance: OpaquePointer?
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Configure VPN
        var config = vpn_config_t()
        
        // Set server details safely
        if let serverAddress = options?["server"] as? String {
            let maxLength = MemoryLayout.size(ofValue: config.server_address) - 1
            let truncated = String(serverAddress.prefix(maxLength))
            truncated.withCString { cString in
                let length = min(strlen(cString), maxLength)
                memcpy(&config.server_address.0, cString, length)
                withUnsafeMutablePointer(to: &config.server_address.0) { ptr in
                    ptr.advanced(by: Int(length)).pointee = 0 // Null terminate
                }
            }
        }
        
        config.server_port = 443
        config.enable_dns_cache = true
        config.enable_privacy_guards = true
        config.timeout_ms = 30000
        config.max_retries = 3
        
        // Set auth token safely
        if let token = options?["authToken"] as? String {
            let maxLength = MemoryLayout.size(ofValue: config.auth_token) - 1
            let truncated = String(token.prefix(maxLength))
            truncated.withCString { cString in
                let length = min(strlen(cString), maxLength)
                memcpy(&config.auth_token.0, cString, length)
                withUnsafeMutablePointer(to: &config.auth_token.0) { ptr in
                    ptr.advanced(by: Int(length)).pointee = 0 // Null terminate
                }
            }
        }
        
        // Create VPN instance
        vpnInstance = relative_vpn_create(&config)
        guard vpnInstance != nil else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        
        // Start VPN
        let result = relative_vpn_start(vpnInstance)
        if result != VPN_SUCCESS {
            completionHandler(NEVPNError(.connectionFailed))
            return
        }
        
        // Configure tunnel settings
        let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: String(cString: &config.server_address.0))
        
        // Configure IPv4
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        tunnelSettings.ipv4Settings = ipv4Settings
        
        // Configure DNS
        tunnelSettings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        
        // Apply settings
        setTunnelNetworkSettings(tunnelSettings) { error in
            completionHandler(error)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if let vpn = vpnInstance {
            relative_vpn_stop(vpn)
            relative_vpn_destroy(vpn)
            vpnInstance = nil
        }
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the containing app
        // Example: status requests, configuration updates
        
        if let vpn = vpnInstance {
            let status = relative_vpn_get_status(vpn)
            let response = withUnsafeBytes(of: status) { Data($0) }
            completionHandler?(response)
        } else {
            completionHandler?(nil)
        }
    }
}
```

### 2. Main App VPN Manager

```swift
import NetworkExtension
import RelativeProtocol

@MainActor
class VPNManager: ObservableObject {
    @Published var vpnStatus: NEVPNStatus = .disconnected
    private var vpnManager: NETunnelProviderManager?
    
    init() {
        loadVPNConfiguration()
        observeVPNStatus()
    }
    
    private func loadVPNConfiguration() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let manager = managers?.first {
                self?.vpnManager = manager
            } else {
                self?.createVPNConfiguration()
            }
        }
    }
    
    private func createVPNConfiguration() {
        let manager = NETunnelProviderManager()
        
        // Configure the protocol
        let protocolConfig = NETunnelProviderProtocol()
        protocolConfig.providerBundleIdentifier = "com.yourcompany.app.tunnel"
        protocolConfig.serverAddress = "vpn.example.com"
        
        // Set provider configuration
        protocolConfig.providerConfiguration = [
            "server": "vpn.example.com",
            "authToken": "your-auth-token"
        ]
        
        manager.protocolConfiguration = protocolConfig
        manager.localizedDescription = "RelativeProtocol VPN"
        manager.isEnabled = true
        
        // Save configuration
        manager.saveToPreferences { [weak self] error in
            if error == nil {
                self?.vpnManager = manager
            }
        }
    }
    
    func connect() {
        guard let manager = vpnManager else { return }
        
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            print("Failed to start VPN: \(error)")
        }
    }
    
    func disconnect() {
        vpnManager?.connection.stopVPNTunnel()
    }
    
    private func observeVPNStatus() {
        Task { @MainActor in
            for await _ in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange) {
                await updateVPNStatus()
            }
        }
    }
    
    private func updateVPNStatus() async {
        vpnStatus = vpnManager?.connection.status ?? .disconnected
    }
}
```

### 3. SwiftUI Integration

```swift
import SwiftUI

struct VPNControlView: View {
    @StateObject private var vpnManager = VPNManager()
    
    var body: some View {
        VStack(spacing: 20) {
            // Status indicator
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                Text(statusText)
                    .font(.headline)
            }
            
            // Connection button
            Button(action: toggleConnection) {
                Text(vpnManager.vpnStatus == .connected ? "Disconnect" : "Connect")
                    .foregroundColor(.white)
                    .padding(.horizontal, 40)
                    .padding(.vertical, 15)
                    .background(
                        vpnManager.vpnStatus == .connected ? Color.red : Color.blue
                    )
                    .cornerRadius(25)
            }
            .disabled(vpnManager.vpnStatus == .connecting || vpnManager.vpnStatus == .disconnecting)
        }
        .padding()
    }
    
    private var statusColor: Color {
        switch vpnManager.vpnStatus {
        case .connected:
            return .green
        case .connecting, .disconnecting:
            return .yellow
        default:
            return .gray
        }
    }
    
    private var statusText: String {
        switch vpnManager.vpnStatus {
        case .connected:
            return "Connected"
        case .connecting:
            return "Connecting..."
        case .disconnecting:
            return "Disconnecting..."
        case .disconnected:
            return "Disconnected"
        default:
            return "Unknown"
        }
    }
    
    private func toggleConnection() {
        if vpnManager.vpnStatus == .connected {
            vpnManager.disconnect()
        } else {
            vpnManager.connect()
        }
    }
}
```

## Best Practices

### 1. Memory Management

When working with C APIs from Swift:

```swift
// Always clean up C resources
defer {
    if let vpn = vpnInstance {
        relative_vpn_destroy(vpn)
    }
}

// Use withUnsafePointer for passing Swift data to C
serverAddress.withCString { cString in
    strncpy(&config.server_address.0, cString, 255)
}
```

### 2. Error Handling

```swift
// Convert C error codes to Swift errors
enum VPNError: Error {
    case invalidConfig
    case connectionFailed
    case authFailed
    case timeout
    case memory
    case network
    
    init?(code: Int32) {
        switch code {
        case -1: self = .invalidConfig
        case -2: self = .connectionFailed
        case -3: self = .authFailed
        case -4: self = .timeout
        case -5: self = .memory
        case -6: self = .network
        default: return nil
        }
    }
}

// Use in your code
let result = relative_vpn_start(vpnInstance)
if result != VPN_SUCCESS {
    if let error = VPNError(code: result) {
        throw error
    }
}
```

### 3. Network Monitoring

```swift
import Network

class NetworkMonitor {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "NetworkMonitor")
    
    func startMonitoring() {
        monitor.pathUpdateHandler = { path in
            if path.status == .satisfied {
                // Network available
                self.handleNetworkAvailable()
            } else {
                // Network unavailable
                self.handleNetworkLost()
            }
        }
        monitor.start(queue: queue)
    }
}
```

### 4. Privacy Guards

Enable privacy features:

```swift
// In your config
config.enable_privacy_guards = true

// Monitor privacy violations
let privacyViolations = relative_vpn_get_privacy_violations(vpnInstance)
if privacyViolations > 0 {
    // Log or alert user about potential privacy issues
}
```

## Troubleshooting

### Common Issues

1. **"unsigned framework" error**
   - Ensure the XCFramework is code-signed
   - Run: `codesign --sign - --deep RelativeProtocol.xcframework`

2. **"file not found" in bridging header**
   - Don't use bridging headers for SPM binary frameworks
   - Import directly in Swift: `import RelativeProtocol`

3. **VPN won't connect**
   - Check NetworkExtension entitlements
   - Verify server configuration
   - Check console logs for detailed errors

4. **Memory leaks**
   - Always call `relative_vpn_destroy()` when done
   - Use proper Swift memory management patterns

### Debug Logging

Enable detailed logging:

```c
// Set log level
log_set_level(LOG_LEVEL_DEBUG);

// Custom log handler
void custom_log_handler(int level, const char* message) {
    NSLog(@"[RelativeVPN] %s", message);
}
log_set_handler(custom_log_handler);
```

### Performance Monitoring

```swift
// Get metrics
if let vpn = vpnInstance {
    let metrics = relative_vpn_get_metrics(vpn)
    print("Packets sent: \(metrics.packets_sent)")
    print("Packets received: \(metrics.packets_received)")
    print("Bytes sent: \(metrics.bytes_sent)")
    print("Bytes received: \(metrics.bytes_received)")
}
```

## Advanced Topics

### Custom DNS Resolution

```swift
// Configure custom DNS
var dnsConfig = dns_config_t()
dnsConfig.primary_server = "1.1.1.1"
dnsConfig.secondary_server = "1.0.0.1"
dnsConfig.cache_size = 1000
dnsConfig.ttl_seconds = 300

relative_vpn_set_dns_config(vpnInstance, &dnsConfig)
```

### MTU Discovery

```swift
// Enable MTU discovery
relative_vpn_enable_mtu_discovery(vpnInstance, true)

// Get optimal MTU
let optimalMTU = relative_vpn_get_optimal_mtu(vpnInstance)
print("Optimal MTU: \(optimalMTU)")
```

### NAT64 Support

```swift
// Enable NAT64 for IPv6-only networks
relative_vpn_enable_nat64(vpnInstance, true)
```

## Security Considerations

1. **Store credentials securely** using Keychain
2. **Validate server certificates** to prevent MITM attacks
3. **Enable privacy guards** to detect potential leaks
4. **Implement certificate pinning** for enhanced security
5. **Use secure random number generation** for tokens

### Privacy Manifest (iOS 17+)

Create a `PrivacyInfo.xcprivacy` file in your project:

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
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <!-- Declare any data collection here -->
    </array>
    <key>NSPrivacyTrackingDomains</key>
    <array>
        <!-- List tracking domains if any -->
    </array>
    <key>NSPrivacyTracking</key>
    <false/>
</dict>
</plist>
```

### Keychain Integration

```swift
import Security

class VPNKeychain {
    private let service = "com.yourcompany.vpn"
    
    func store(token: String, for account: String) throws {
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw VPNError.keychain(status)
        }
    }
    
    func retrieve(for account: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            throw VPNError.keychain(status)
        }
        
        return token
    }
}

## Support and Contributing

For issues, feature requests, or contributions:
- GitHub Issues: https://github.com/yourusername/relativeProtocol/issues
- Documentation: https://github.com/yourusername/relativeProtocol/wiki

## License

RelativeProtocol is licensed under the GNU General Public License v3.0. See LICENSE for details.