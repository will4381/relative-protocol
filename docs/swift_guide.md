# Swift Wrapper Guide for RelativeProtocol

This guide shows how to create a Swift wrapper around the RelativeProtocol C API to provide a more idiomatic Swift interface.

## Why Create a Swift Wrapper?

While you can use the C API directly from Swift, a wrapper provides:
- Type safety with Swift enums and structs
- Automatic memory management
- Async/await support
- Error handling with Swift's Result type
- SwiftUI-friendly ObservableObject patterns
- Elimination of unsafe pointer operations

## Basic Swift Wrapper Implementation

### 1. Core VPN Manager

```swift
import Foundation
import RelativeProtocol

/// Main VPN manager class providing a Swift-friendly interface
@MainActor
public class RelativeVPNManager {
    private var vpnInstance: OpaquePointer?
    private let queue = DispatchQueue(label: "com.relative.vpn", qos: .userInitiated)
    
    /// VPN connection status
    public enum ConnectionStatus {
        case disconnected
        case connecting
        case connected
        case disconnecting
        case reconnecting
        
        init(from cStatus: vpn_status_t) {
            switch cStatus {
            case VPN_STATUS_DISCONNECTED:
                self = .disconnected
            case VPN_STATUS_CONNECTING:
                self = .connecting
            case VPN_STATUS_CONNECTED:
                self = .connected
            case VPN_STATUS_DISCONNECTING:
                self = .disconnecting
            case VPN_STATUS_RECONNECTING:
                self = .reconnecting
            default:
                self = .disconnected
            }
        }
    }
    
    /// VPN errors
    public enum VPNError: LocalizedError {
        case invalidConfiguration
        case connectionFailed
        case authenticationFailed
        case timeout
        case memoryError
        case networkError
        case alreadyConnected
        case notConnected
        
        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration:
                return "Invalid VPN configuration"
            case .connectionFailed:
                return "Failed to establish VPN connection"
            case .authenticationFailed:
                return "Authentication failed"
            case .timeout:
                return "Connection timed out"
            case .memoryError:
                return "Memory allocation error"
            case .networkError:
                return "Network error"
            case .alreadyConnected:
                return "VPN is already connected"
            case .notConnected:
                return "VPN is not connected"
            }
        }
        
        init?(from errorCode: Int32) {
            switch errorCode {
            case -1: self = .invalidConfiguration
            case -2: self = .connectionFailed
            case -3: self = .authenticationFailed
            case -4: self = .timeout
            case -5: self = .memoryError
            case -6: self = .networkError
            default: return nil
            }
        }
    }
    
    /// VPN configuration
    public struct Configuration {
        public let serverAddress: String
        public let serverPort: UInt16
        public let authToken: String
        public let maxRetries: UInt32
        public let timeoutSeconds: TimeInterval
        public let enableDNSCache: Bool
        public let enablePrivacyGuards: Bool
        
        public init(
            serverAddress: String,
            serverPort: UInt16 = 443,
            authToken: String,
            maxRetries: UInt32 = 3,
            timeoutSeconds: TimeInterval = 30,
            enableDNSCache: Bool = true,
            enablePrivacyGuards: Bool = true
        ) {
            self.serverAddress = serverAddress
            self.serverPort = serverPort
            self.authToken = authToken
            self.maxRetries = maxRetries
            self.timeoutSeconds = timeoutSeconds
            self.enableDNSCache = enableDNSCache
            self.enablePrivacyGuards = enablePrivacyGuards
        }
    }
    
    public init() {}
    
    deinit {
        disconnect()
    }
    
    /// Connect to VPN with async/await
    public func connect(configuration: Configuration) async throws {
        // Ensure we're not already connected
        guard vpnInstance == nil else {
            throw VPNError.alreadyConnected
        }
        
        // Perform connection on background queue but return to MainActor
        try await Task.detached { [weak self] in
            try await self?.performConnection(configuration: configuration)
        }.value
    }
    
    private func performConnection(configuration: Configuration) async throws {
        var config = vpn_config_t()
        
        // Safe string copying
        try await Task.detached {
            try self.copyStringToBuffer(configuration.serverAddress, to: &config.server_address.0, maxLength: 255)
            try self.copyStringToBuffer(configuration.authToken, to: &config.auth_token.0, maxLength: 511)
        }.value
        
        config.server_port = configuration.serverPort
        config.max_retries = configuration.maxRetries
        config.timeout_ms = UInt32(configuration.timeoutSeconds * 1000)
        config.enable_dns_cache = configuration.enableDNSCache
        config.enable_privacy_guards = configuration.enablePrivacyGuards
        
        // Create and start VPN
        guard let instance = relative_vpn_create(&config) else {
            throw VPNError.invalidConfiguration
        }
        
        let result = relative_vpn_start(instance)
        if result == VPN_SUCCESS {
            await MainActor.run {
                self.vpnInstance = instance
            }
        } else {
            relative_vpn_destroy(instance)
            if let error = VPNError(from: result) {
                throw error
            } else {
                throw VPNError.connectionFailed
            }
        }
    }
    
    private func copyStringToBuffer(_ string: String, to buffer: UnsafeMutablePointer<CChar>, maxLength: Int) throws {
        let maxLength = maxLength - 1 // Leave space for null terminator
        let truncated = String(string.prefix(maxLength))
        
        truncated.withCString { cString in
            let length = min(strlen(cString), maxLength)
            memcpy(buffer, cString, length)
            buffer.advanced(by: Int(length)).pointee = 0 // Null terminate
        }
    }
    
    /// Connect to VPN with completion handler
    public func connect(configuration: Configuration, completion: @escaping (Result<Void, VPNError>) -> Void) {
        queue.async {
            self.connectSync(configuration: configuration, completion: completion)
        }
    }
    
    private func connectSync(configuration: Configuration, completion: @escaping (Result<Void, VPNError>) -> Void) {
        // Check if already connected
        if vpnInstance != nil {
            completion(.failure(.alreadyConnected))
            return
        }
        
        // Create C config struct
        var config = vpn_config_t()
        
        // Copy server address
        configuration.serverAddress.withCString { cString in
            strncpy(&config.server_address.0, cString, 255)
        }
        
        // Copy auth token
        configuration.authToken.withCString { cString in
            strncpy(&config.auth_token.0, cString, 511)
        }
        
        // Set other parameters
        config.server_port = configuration.serverPort
        config.max_retries = configuration.maxRetries
        config.timeout_ms = UInt32(configuration.timeoutSeconds * 1000)
        config.enable_dns_cache = configuration.enableDNSCache
        config.enable_privacy_guards = configuration.enablePrivacyGuards
        
        // Create VPN instance
        guard let instance = relative_vpn_create(&config) else {
            completion(.failure(.invalidConfiguration))
            return
        }
        
        vpnInstance = instance
        
        // Start VPN
        let result = relative_vpn_start(instance)
        if result == VPN_SUCCESS {
            completion(.success(()))
        } else {
            relative_vpn_destroy(instance)
            vpnInstance = nil
            
            if let error = VPNError(from: result) {
                completion(.failure(error))
            } else {
                completion(.failure(.connectionFailed))
            }
        }
    }
    
    /// Disconnect from VPN
    public func disconnect() {
        queue.sync {
            guard let instance = vpnInstance else { return }
            
            relative_vpn_stop(instance)
            relative_vpn_destroy(instance)
            vpnInstance = nil
        }
    }
    
    /// Get current connection status
    public var status: ConnectionStatus {
        get async {
            guard let instance = vpnInstance else {
                return .disconnected
            }
            
            return await Task.detached {
                let cStatus = relative_vpn_get_status(instance)
                return ConnectionStatus(from: cStatus)
            }.value
        }
    }
    
    /// Get connection metrics
    public var metrics: ConnectionMetrics? {
        get async {
            guard let instance = vpnInstance else { return nil }
            
            return await Task.detached {
                var cMetrics = vpn_metrics_t()
                relative_vpn_get_metrics(instance, &cMetrics)
                
                return ConnectionMetrics(
                    bytesSent: Int(cMetrics.bytes_sent),
                    bytesReceived: Int(cMetrics.bytes_received),
                    packetsSent: Int(cMetrics.packets_sent),
                    packetsReceived: Int(cMetrics.packets_received),
                    connectionDuration: TimeInterval(cMetrics.connection_duration_seconds),
                    lastError: cMetrics.last_error_code != 0 ? VPNError(from: cMetrics.last_error_code) : nil
                )
            }.value
        }
    }
}

/// Connection metrics
public struct ConnectionMetrics {
    public let bytesSent: Int
    public let bytesReceived: Int
    public let packetsSent: Int
    public let packetsReceived: Int
    public let connectionDuration: TimeInterval
    public let lastError: RelativeVPNManager.VPNError?
}
```

### 2. SwiftUI ObservableObject Wrapper

```swift
import SwiftUI
import Combine

/// Observable VPN manager for SwiftUI
@MainActor
public class ObservableVPNManager: ObservableObject {
    @Published public private(set) var status: RelativeVPNManager.ConnectionStatus = .disconnected
    @Published public private(set) var metrics: ConnectionMetrics?
    @Published public private(set) var isConnecting = false
    @Published public private(set) var lastError: RelativeVPNManager.VPNError?
    
    private let vpnManager = RelativeVPNManager()
    private var monitoringTask: Task<Void, Never>?
    
    public init() {
        startStatusMonitoring()
    }
    
    deinit {
        monitoringTask?.cancel()
    }
    
    private func startStatusMonitoring() {
        monitoringTask = Task { @MainActor in
            await withTaskGroup(of: Void.self) { group in
                // Monitor status changes
                group.addTask { @MainActor in
                    for await newStatus in self.vpnManager.statusStream() {
                        self.status = newStatus
                        if newStatus == .connected || newStatus == .disconnected {
                            self.isConnecting = false
                        }
                    }
                }
                
                // Monitor metrics changes
                group.addTask { @MainActor in
                    for await newMetrics in self.vpnManager.metricsStream() {
                        self.metrics = newMetrics
                    }
                }
            }
        }
    }
    
    public func connect(configuration: RelativeVPNManager.Configuration) {
        Task {
            isConnecting = true
            lastError = nil
            
            do {
                try await vpnManager.connect(configuration: configuration)
                updateStatus()
            } catch let error as RelativeVPNManager.VPNError {
                lastError = error
                isConnecting = false
            } catch {
                lastError = .connectionFailed
                isConnecting = false
            }
        }
    }
    
    public func disconnect() {
        vpnManager.disconnect()
        updateStatus()
    }
}
```

### 3. DNS Configuration Wrapper

```swift
/// DNS configuration wrapper
public struct DNSConfiguration {
    public let primaryServer: String
    public let secondaryServer: String?
    public let cacheSize: Int
    public let ttlSeconds: TimeInterval
    
    public init(
        primaryServer: String = "1.1.1.1",
        secondaryServer: String? = "1.0.0.1",
        cacheSize: Int = 1000,
        ttlSeconds: TimeInterval = 300
    ) {
        self.primaryServer = primaryServer
        self.secondaryServer = secondaryServer
        self.cacheSize = cacheSize
        self.ttlSeconds = ttlSeconds
    }
}

extension RelativeVPNManager {
    /// Configure DNS settings
    public func configureDNS(_ configuration: DNSConfiguration) throws {
        guard let instance = vpnInstance else {
            throw VPNError.notConnected
        }
        
        var dnsConfig = dns_config_t()
        
        configuration.primaryServer.withCString { cString in
            strncpy(&dnsConfig.primary_server.0, cString, 255)
        }
        
        if let secondary = configuration.secondaryServer {
            secondary.withCString { cString in
                strncpy(&dnsConfig.secondary_server.0, cString, 255)
            }
        }
        
        dnsConfig.cache_size = UInt32(configuration.cacheSize)
        dnsConfig.ttl_seconds = UInt32(configuration.ttlSeconds)
        
        let result = relative_vpn_set_dns_config(instance, &dnsConfig)
        if result != VPN_SUCCESS {
            throw VPNError(from: result) ?? .networkError
        }
    }
}
```

### 4. Privacy Monitoring

```swift
/// Privacy violation types
public struct PrivacyViolation {
    public enum ViolationType {
        case dnsLeak
        case ipLeak
        case webRTCLeak
        case tlsCertificateIssue
        case other(String)
    }
    
    public let type: ViolationType
    public let timestamp: Date
    public let details: String
}

extension RelativeVPNManager {
    /// Get privacy violations
    public func getPrivacyViolations() async -> [PrivacyViolation] {
        guard let instance = vpnInstance else { return [] }
        
        return await Task.detached {
            var violations: [PrivacyViolation] = []
            
            // Get violation count
            let count = relative_vpn_get_privacy_violations_count(instance)
            guard count > 0 else { return [] }
            
            // Safely allocate buffer for violations with proper error handling
            let bufferSize = Int(count)
            guard bufferSize <= 1000 else { // Reasonable safety limit
                print("Warning: Privacy violations count (\(count)) exceeds safety limit")
                return []
            }
            
            let buffer = UnsafeMutablePointer<privacy_violation_t>.allocate(capacity: bufferSize)
            defer { 
                buffer.deinitialize(count: bufferSize)
                buffer.deallocate() 
            }
            
            // Initialize the buffer
            buffer.initialize(repeating: privacy_violation_t(), count: bufferSize)
            
            // Get violations with error checking
            let actualCount = relative_vpn_get_privacy_violations(instance, buffer, count)
            guard actualCount <= count else {
                print("Error: Privacy violations returned more than expected")
                return []
            }
            
            // Convert to Swift types safely
            for i in 0..<Int(min(actualCount, count)) {
                let cViolation = buffer[i]
                
                let type: PrivacyViolation.ViolationType
                switch cViolation.type {
                case VIOLATION_DNS_LEAK:
                    type = .dnsLeak
                case VIOLATION_IP_LEAK:
                    type = .ipLeak
                case VIOLATION_WEBRTC_LEAK:
                    type = .webRTCLeak
                case VIOLATION_TLS_ISSUE:
                    type = .tlsCertificateIssue
                default:
                    // Safe string conversion
                    let typeString = withUnsafePointer(to: &cViolation.type_string.0) { ptr in
                        String(cString: ptr)
                    }
                    type = .other(typeString)
                }
                
                // Safe string conversion for details
                let details = withUnsafePointer(to: &cViolation.details.0) { ptr in
                    String(cString: ptr)
                }
                
                let violation = PrivacyViolation(
                    type: type,
                    timestamp: Date(timeIntervalSince1970: TimeInterval(cViolation.timestamp)),
                    details: details
                )
                
                violations.append(violation)
            }
            
            return violations
        }.value
    }
}
```

### 5. Async Stream for Real-time Updates

```swift
extension RelativeVPNManager {
    /// Stream of status updates
    public func statusStream() -> AsyncStream<ConnectionStatus> {
        AsyncStream { continuation in
            let timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
                continuation.yield(self.status)
            }
            
            continuation.onTermination = { _ in
                timer.invalidate()
            }
        }
    }
    
    /// Stream of metrics updates
    public func metricsStream() -> AsyncStream<ConnectionMetrics?> {
        AsyncStream { continuation in
            let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
                continuation.yield(self.metrics)
            }
            
            continuation.onTermination = { _ in
                timer.invalidate()
            }
        }
    }
}
```

## Usage Examples

### Basic Connection

```swift
import SwiftUI

struct VPNView: View {
    @StateObject private var vpnManager = ObservableVPNManager()
    @State private var serverAddress = "vpn.example.com"
    @State private var authToken = ""
    
    var body: some View {
        VStack(spacing: 20) {
            // Status
            Label(statusText, systemImage: statusIcon)
                .foregroundColor(statusColor)
            
            // Metrics
            if let metrics = vpnManager.metrics {
                VStack(alignment: .leading) {
                    Text("Sent: \(formatBytes(metrics.bytesSent))")
                    Text("Received: \(formatBytes(metrics.bytesReceived))")
                    Text("Duration: \(formatDuration(metrics.connectionDuration))")
                }
                .font(.caption)
            }
            
            // Connection button
            Button(action: toggleConnection) {
                if vpnManager.isConnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                } else {
                    Text(vpnManager.status == .connected ? "Disconnect" : "Connect")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(vpnManager.isConnecting)
            
            // Error display
            if let error = vpnManager.lastError {
                Text(error.localizedDescription)
                    .foregroundColor(.red)
                    .font(.caption)
            }
        }
        .padding()
    }
    
    private var statusText: String {
        switch vpnManager.status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnected: return "Disconnected"
        case .disconnecting: return "Disconnecting..."
        case .reconnecting: return "Reconnecting..."
        }
    }
    
    private var statusIcon: String {
        switch vpnManager.status {
        case .connected: return "lock.shield.fill"
        case .connecting, .reconnecting: return "arrow.triangle.2.circlepath"
        case .disconnected, .disconnecting: return "lock.shield"
        }
    }
    
    private var statusColor: Color {
        switch vpnManager.status {
        case .connected: return .green
        case .connecting, .reconnecting: return .orange
        case .disconnected, .disconnecting: return .gray
        }
    }
    
    private func toggleConnection() {
        if vpnManager.status == .connected {
            vpnManager.disconnect()
        } else {
            let config = RelativeVPNManager.Configuration(
                serverAddress: serverAddress,
                authToken: authToken
            )
            vpnManager.connect(configuration: config)
        }
    }
    
    private func formatBytes(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        return formatter.string(fromByteCount: Int64(bytes))
    }
    
    private func formatDuration(_ seconds: TimeInterval) -> String {
        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: seconds) ?? ""
    }
}
```

### Advanced Usage with Async/Await

```swift
class VPNService {
    private let vpnManager = RelativeVPNManager()
    
    func connectWithRetry(config: RelativeVPNManager.Configuration, maxAttempts: Int = 3) async throws {
        var lastError: Error?
        
        for attempt in 1...maxAttempts {
            do {
                try await vpnManager.connect(configuration: config)
                return // Success
            } catch {
                lastError = error
                print("Connection attempt \(attempt) failed: \(error)")
                
                if attempt < maxAttempts {
                    // Wait before retry with exponential backoff
                    try await Task.sleep(nanoseconds: UInt64(pow(2.0, Double(attempt)) * 1_000_000_000))
                }
            }
        }
        
        throw lastError ?? RelativeVPNManager.VPNError.connectionFailed
    }
    
    func monitorConnection() async {
        for await status in vpnManager.statusStream() {
            print("VPN Status: \(status)")
            
            if status == .disconnected {
                // Handle unexpected disconnection
                await handleDisconnection()
            }
        }
    }
    
    private func handleDisconnection() async {
        // Implement reconnection logic
    }
}
```

### Privacy Monitoring

```swift
class PrivacyMonitor {
    private let vpnManager = RelativeVPNManager()
    
    func startMonitoring() {
        Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { _ in
            self.checkPrivacyViolations()
        }
    }
    
    private func checkPrivacyViolations() {
        let violations = vpnManager.getPrivacyViolations()
        
        for violation in violations {
            switch violation.type {
            case .dnsLeak:
                print("⚠️ DNS Leak detected: \(violation.details)")
                // Alert user or take corrective action
            case .ipLeak:
                print("⚠️ IP Leak detected: \(violation.details)")
            case .tlsCertificateIssue:
                print("⚠️ TLS Certificate issue: \(violation.details)")
            default:
                print("⚠️ Privacy violation: \(violation.details)")
            }
        }
    }
}
```

## Testing the Wrapper

```swift
import XCTest

class RelativeVPNManagerTests: XCTestCase {
    var vpnManager: RelativeVPNManager!
    
    override func setUp() {
        super.setUp()
        vpnManager = RelativeVPNManager()
    }
    
    override func tearDown() {
        vpnManager.disconnect()
        vpnManager = nil
        super.tearDown()
    }
    
    func testConnection() async throws {
        let config = RelativeVPNManager.Configuration(
            serverAddress: "test.vpn.com",
            authToken: "test-token"
        )
        
        try await vpnManager.connect(configuration: config)
        
        XCTAssertEqual(vpnManager.status, .connected)
        XCTAssertNotNil(vpnManager.metrics)
    }
    
    func testInvalidConfiguration() async {
        let config = RelativeVPNManager.Configuration(
            serverAddress: "",
            authToken: ""
        )
        
        do {
            try await vpnManager.connect(configuration: config)
            XCTFail("Should have thrown error")
        } catch let error as RelativeVPNManager.VPNError {
            XCTAssertEqual(error, .invalidConfiguration)
        }
    }
}
```

## Integration with Existing Code

If you already have a packet tunnel provider, integrate the wrapper:

```swift
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let vpnManager = RelativeVPNManager()
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let serverAddress = options?["server"] as? String,
              let authToken = options?["authToken"] as? String else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        
        let config = RelativeVPNManager.Configuration(
            serverAddress: serverAddress,
            authToken: authToken
        )
        
        Task {
            do {
                try await vpnManager.connect(configuration: config)
                
                // Configure tunnel network settings
                let settings = createTunnelSettings(serverAddress: serverAddress)
                try await setTunnelNetworkSettings(settings)
                
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        vpnManager.disconnect()
        completionHandler()
    }
}
```

## Performance Considerations

1. **Use async/await** for better performance and cleaner code
2. **Cache frequently accessed values** like status and metrics
3. **Batch operations** when possible
4. **Use Combine or AsyncStream** for reactive updates
5. **Minimize main thread blocking** with proper queue management

## Next Steps

1. Add more specialized wrappers for specific features
2. Implement Combine publishers for reactive programming
3. Add SwiftUI property wrappers for easier integration
4. Create unit tests for all wrapper functionality
5. Add documentation comments for better Xcode integration