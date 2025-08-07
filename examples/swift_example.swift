/**
 * RelativeProtocol VPN - Swift Example with Extensive Logging
 * 
 * This example demonstrates how to use the RelativeProtocol VPN with extensive logging
 * to debug network connectivity and packet forwarding issues.
 * 
 * USAGE:
 * 1. To enable TRACE logging (most verbose):
 *    - Set log_level = "TRACE" in tunnel options
 *    - Or modify logLevel property below
 * 
 * 2. To enable DEBUG logging (packet summaries):
 *    - Set log_level = "DEBUG" in tunnel options
 * 
 * 3. Available log levels:
 *    - TRACE: Every packet detail, header parsing, buffer operations
 *    - DEBUG: Packet summaries, connection tracking, DNS queries
 *    - INFO: Component initialization, statistics (default)
 *    - WARN: Potential issues, recoverable errors
 *    - ERROR: Actual errors, failed operations
 *    - CRITICAL: Critical failures only
 *    - SILENT: No logging
 * 
 * The extensive logging will help you identify:
 * - Where packets are being dropped
 * - Connection tracking issues
 * - Header reconstruction problems
 * - DNS resolution failures  
 * - NAT64 translation problems
 */

import NetworkExtension
import RelativeProtocol
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = Logger(subsystem: "com.relativeprotocol.vpn", category: "PacketTunnelProvider")
    private var isProcessingPackets = false
    
    // RelativeProtocol components (using actual working modules)
    private var dnsResolver: OpaquePointer?
    private var connectionManager: OpaquePointer?
    private var nat64Translator: OpaquePointer?
    
    // Logging configuration - change this to "TRACE" or "DEBUG" for extensive debugging
    private var logLevel: String = "DEBUG"
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting RelativeProtocol on-device VPN...")
        
        // Configure extensive logging based on options
        if let logLevelOption = options?["log_level"] as? String {
            logLevel = logLevelOption
        }
        
        // Enable extensive logging for debugging network issues
        logger.info("Setting log level to: \(logLevel)")
        setupExtensiveLogging()
        
        // Initialize RelativeProtocol core with logging
        logger.info("Initializing RelativeProtocol core components...")
        let vpnInitialized = ios_vpn_init()
        guard vpnInitialized else {
            logger.error("Failed to initialize iOS VPN core")
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        // Initialize DNS resolver for Google DNS
        var dnsServer = ip_addr_t()
        dnsServer.v4.addr = 0x08080808  // 8.8.8.8 in network byte order
        dnsResolver = dns_resolver_create(&dnsServer, 53)
        guard dnsResolver != nil else {
            logger.error("Failed to create DNS resolver")
            ios_vpn_cleanup()
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        // Initialize connection manager
        connectionManager = connection_manager_create()
        guard connectionManager != nil else {
            logger.error("Failed to create connection manager")
            if let resolver = dnsResolver {
                dns_resolver_destroy(resolver)
            }
            ios_vpn_cleanup()
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        // Initialize NAT64 translator
        nat64Translator = nat64_translator_create(nil, 0)
        guard nat64Translator != nil else {
            logger.error("Failed to create NAT64 translator")
            if let resolver = dnsResolver {
                dns_resolver_destroy(resolver)
            }
            if let manager = connectionManager {
                connection_manager_destroy(manager)
            }
            ios_vpn_cleanup()
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        logger.info("✅ All RelativeProtocol components initialized")
        
        // Configure network settings for the tunnel
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        
        // Configure IPv4 settings - route all traffic through tunnel
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()] // Route all traffic
        networkSettings.ipv4Settings = ipv4Settings
        
        // Configure DNS to prevent leaks
        let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        networkSettings.dnsSettings = dnsSettings
        
        // Apply network settings
        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to set tunnel network settings: \(error.localizedDescription)")
                self?.cleanup()
                completionHandler(error)
                return
            }
            
            self?.logger.info("✅ Network settings applied - all traffic routed through VPN")
            
            // Start packet processing
            self?.isProcessingPackets = true
            self?.startPacketProcessing()
            
            self?.logger.info("🚀 RelativeProtocol on-device VPN is active")
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping RelativeProtocol VPN...")
        
        // Stop packet processing
        isProcessingPackets = false
        
        // Cleanup all components
        cleanup()
        
        logger.info("✅ RelativeProtocol VPN stopped")
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        logger.debug("Received app message: \(messageData.count) bytes")
        
        // Could handle configuration updates or status requests
        // For now, just acknowledge
        completionHandler?(Data())
    }
    
    private func startPacketProcessing() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isProcessingPackets else { return }
            
            var processedPackets: [Data] = []
            
            // Process each packet through RelativeProtocol
            for (index, packet) in packets.enumerated() {
                if let processedPacket = self.processPacket(packet, protocolNumber: protocols[index]) {
                    processedPackets.append(processedPacket)
                }
            }
            
            // Forward processed packets to internet
            if !processedPackets.isEmpty {
                let protocolNumbers = Array(protocols.prefix(processedPackets.count))
                self.packetFlow.writePackets(processedPackets, withProtocols: protocolNumbers)
            }
            
            // Continue reading packets
            self.startPacketProcessing()
        }
    }
    
    private func processPacket(_ packet: Data, protocolNumber: NSNumber) -> Data? {
        guard packet.count > 0 else { return nil }
        
        return packet.withUnsafeBytes { bytes in
            guard let packetPtr = bytes.bindMemory(to: UInt8.self).baseAddress else { return packet }
            let packetLength = packet.count
            
            // Log packet reception for debugging
            if logLevel == "TRACE" || logLevel == "DEBUG" {
                logger.debug("📦 Processing incoming packet: \(packetLength) bytes, protocol family: \(protocolNumber)")
            }
            
            // Parse packet using RelativeProtocol - this will generate extensive logging
            var packetInfo = packet_info_t()
            let parsed = ios_vpn_parse_packet(packetPtr, packetLength, &packetInfo)
            guard parsed else {
                logger.warning("❌ Failed to parse packet (\(packetLength) bytes), passing through unchanged")
                return packet
            }
            
            // Log successful parsing
            if logLevel == "DEBUG" {
                let srcIP = String(cString: ios_vpn_ip_to_string(packetInfo.flow.src_ip))
                let dstIP = String(cString: ios_vpn_ip_to_string(packetInfo.flow.dst_ip)) 
                let protocolName = String(cString: ios_vpn_protocol_name(packetInfo.flow.protocol))
                logger.debug("✅ Parsed \(protocolName) packet: \(srcIP):\(packetInfo.flow.src_port) → \(dstIP):\(packetInfo.flow.dst_port)")
            }
            
            // Track connection for stateful processing - this generates connection tracking logs
            let connectionHandle = ios_vpn_track_connection(&packetInfo.flow)
            if connectionHandle != nil && (logLevel == "DEBUG" || logLevel == "TRACE") {
                logger.debug("🔗 Connection tracked for flow")
            }
            
            // Process DNS queries
            if ios_vpn_is_dns_packet(&packetInfo), let resolver = dnsResolver {
                logger.debug("🔍 Processing DNS query to \(String(cString: ios_vpn_ip_to_string(packetInfo.flow.dst_ip)))")
                // Convert uint32_t IP to ip_addr_t for DNS resolver
                var srcAddr = ip_addr_t()
                srcAddr.v4.addr = packetInfo.flow.src_ip
                let processed = dns_resolver_process_packet(resolver, packetPtr, packetLength, &srcAddr, packetInfo.flow.src_port)
                if processed && logLevel == "DEBUG" {
                    logger.debug("✅ DNS packet processed successfully")
                }
                // Note: DNS processing is asynchronous, so we still forward the original packet
            }
            
            // Process through connection manager for state tracking
            if let manager = connectionManager {
                connection_manager_process_packet(manager, &packetInfo)
                connection_manager_process_events(manager)
            }
            
            // Handle IPv6 NAT64 translation if needed
            if packetLength > 40 && (packetPtr[0] >> 4) == 6 {
                var ipv6Flow = flow_info_v6_t()
                if ios_vpn_parse_packet_v6(packetPtr, packetLength, &ipv6Flow) &&
                   ios_vpn_needs_nat64(&ipv6Flow),
                   let translator = nat64Translator {
                    
                    logger.debug("🔄 Performing NAT64 translation")
                    var translatedBuffer = [UInt8](repeating: 0, count: Int(packetLength))
                    var translatedSize: size_t = 0
                    
                    let translated = nat64_translate_6to4(translator, packetPtr, packetLength,
                                                        &translatedBuffer, &translatedSize, translatedBuffer.count)
                    if translated && translatedSize > 0 {
                        return Data(translatedBuffer.prefix(Int(translatedSize)))
                    }
                }
            }
            
            // Log flow information periodically
            if Bool.random() && Double.random(in: 0...1) < 0.001 { // 0.1% sampling
                if let srcIP = ios_vpn_ip_to_string(packetInfo.flow.src_ip),
                   let dstIP = ios_vpn_ip_to_string(packetInfo.flow.dst_ip),
                   let protocolName = ios_vpn_protocol_name(packetInfo.flow.protocol) {
                    logger.debug("📊 Processing \(String(cString: protocolName)) packet: \(String(cString: srcIP)):\(packetInfo.flow.src_port) → \(String(cString: dstIP)):\(packetInfo.flow.dst_port)")
                }
            }
            
            // Forward packet to internet (maintaining connectivity)
            return packet
        }
    }
    
    private func cleanup() {
        // Clean up all RelativeProtocol components
        if let resolver = dnsResolver {
            dns_resolver_destroy(resolver)
            dnsResolver = nil
        }
        
        if let manager = connectionManager {
            connection_manager_destroy(manager)
            connectionManager = nil
        }
        
        if let translator = nat64Translator {
            nat64_translator_destroy(translator)
            nat64Translator = nil
        }
        
        // Cleanup core VPN module
        ios_vpn_cleanup()
        
        logger.info("🧹 All RelativeProtocol components cleaned up")
    }
    
    // MARK: - Extensive Logging Setup
    private func setupExtensiveLogging() {
        // Set up VPN logging with custom callback
        let logCallback: @convention(c) (UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { messagePtr, userDataPtr in
            guard let messagePtr = messagePtr else { return }
            let message = String(cString: messagePtr)
            
            // Get the logger instance from user data
            if let userDataPtr = userDataPtr {
                let loggerPtr = userDataPtr.assumingMemoryBound(to: Logger.self)
                let logger = loggerPtr.pointee
                logger.debug("🔧 [VPN-Core] \(message)")
            } else {
                // Fallback to print if no logger available
                print("🔧 [VPN-Core] \(message)")
            }
        }
        
        // Set the log callback with self.logger as user data
        withUnsafePointer(to: logger) { loggerPtr in
            vpn_set_log_callback(logCallback, UnsafeMutableRawPointer(mutating: loggerPtr))
        }
        
        // Set the desired log level for extensive debugging
        vpn_set_log_level(logLevel)
        
        logger.info("✅ Extensive logging configured at level: \(logLevel)")
        logger.info("📝 Available log levels: TRACE (most verbose), DEBUG, INFO, WARN, ERROR, CRITICAL, SILENT")
        
        // Log some examples of what each level shows
        switch logLevel {
        case "TRACE":
            logger.info("🔍 TRACE level will show: Every packet header, checksum calculations, buffer operations")
        case "DEBUG":
            logger.info("🔍 DEBUG level will show: Packet summaries, connection tracking, translation events")
        case "INFO":
            logger.info("🔍 INFO level will show: Component initialization, configuration changes, statistics")
        default:
            logger.info("🔍 Using log level: \(logLevel)")
        }
    }

// MARK: - Error Types
enum PacketTunnelError: Error, LocalizedError {
    case startFailed
    case configurationFailed
    case networkSettingsFailed
    case componentInitializationFailed
    
    var errorDescription: String? {
        switch self {
        case .startFailed:
            return "Failed to start RelativeProtocol VPN"
        case .configurationFailed:
            return "Failed to configure VPN components"
        case .networkSettingsFailed:
            return "Failed to apply network routing settings"
        case .componentInitializationFailed:
            return "Failed to initialize RelativeProtocol components"
        }
    }
}

// MARK: - VPN Statistics (Optional Extension)
extension PacketTunnelProvider {
    
    private func logVPNStatistics() {
        var stats = vpn_stats_t()
        ios_vpn_get_stats(&stats)
        
        logger.info("📊 VPN Stats - Packets: \(stats.packets_processed), Connections: \(stats.active_connections)")
        
        if let manager = connectionManager {
            let tcpCount = connection_manager_get_tcp_count(manager)
            let udpCount = connection_manager_get_udp_count(manager)
            logger.info("📊 Connections - TCP: \(tcpCount), UDP: \(udpCount)")
        }
    }
    
    private func startPeriodicStatistics() {
        Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            guard let self = self, self.isProcessingPackets else { return }
            self.logVPNStatistics()
        }
    }
}