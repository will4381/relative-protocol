import NetworkExtension
import RelativeProtocol
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = Logger(subsystem: "relative-companies.Scroll.ScrollMonitorExtension", category: "PacketTunnelProvider")
    private var isProcessingPackets = false
    
    // RelativeProtocol individual components (no VPN engine needed)
    private var dnsResolver: OpaquePointer?
    private var privacyGuards: OpaquePointer?
    private var trafficClassifier: OpaquePointer?
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting packet tunnel with RelativeProtocol...")
        
        // STEP 1: Initialize RelativeProtocol components (no VPN engine needed)
        logger.info("Initializing RelativeProtocol packet processing components...")
        
        // Create DNS resolver for 8.8.8.8
        var dnsServer = ip_addr_t()
        dnsServer.v4.addr = 0x08080808  // 8.8.8.8 in network byte order
        dnsResolver = dns_resolver_create(&dnsServer, 53)
        guard dnsResolver != nil else {
            logger.error("Failed to create DNS resolver")
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        // Skip privacy guards for now (they're blocking all traffic)
        logger.info("⚠️ Skipping privacy guards to allow internet traffic")
        
        // Create traffic classifier
        trafficClassifier = traffic_classifier_create()
        guard trafficClassifier != nil else {
            logger.error("Failed to create traffic classifier")
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        logger.info("✅ RelativeProtocol components initialized successfully")
        
        // Configure network settings for the tunnel
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        
        // Configure IPv4 settings
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        networkSettings.ipv4Settings = ipv4Settings
        
        // Configure DNS settings to prevent leaks
        let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        networkSettings.dnsSettings = dnsSettings
        
        // Apply network settings
        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to set tunnel network settings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            
            self?.logger.info("Tunnel network settings applied successfully")
            
            // STEP 2: Start manual packet processing
            self?.isProcessingPackets = true
            self?.logger.info("🚀 Starting manual packet processing with RelativeProtocol components")
            
            // Begin processing packets manually
            self?.startManualPacketProcessing()
            
            // Set up metrics monitoring if needed
            self?.setupMetricsMonitoring()
            
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping packet tunnel...")
        
        // Clean up RelativeProtocol components
        if let resolver = dnsResolver {
            dns_resolver_destroy(resolver)
            self.dnsResolver = nil
        }
        
        // Privacy guards not created, nothing to destroy
        
        if let classifier = trafficClassifier {
            traffic_classifier_destroy(classifier)
            self.trafficClassifier = nil
        }
        
        // Stop packet processing
        if isProcessingPackets {
            isProcessingPackets = false
            logger.info("RelativeProtocol packet processing stopped")
        }
        
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        logger.debug("Received app message: \(messageData.count) bytes")
        
        // Handle messages from the main app if needed
        // For now, just acknowledge receipt
        completionHandler?(Data())
    }
    
    private func startManualPacketProcessing() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isProcessingPackets else { return }
            
            // Process each packet through RelativeProtocol components
            for (index, packet) in packets.enumerated() {
                self.processPacketManually(packet, protocolNumber: protocols[index])
            }
            
            // Continue reading packets
            self.startManualPacketProcessing()
        }
    }
    
    private func processPacketManually(_ packet: Data, protocolNumber: NSNumber) {
        guard packet.count > 0 else { return }
        
        packet.withUnsafeBytes { bytes in
            guard let packetPtr = bytes.bindMemory(to: UInt8.self).baseAddress else { return }
            let packetLength = packet.count
            
            // Parse basic packet info (simplified)
            var flow = flow_tuple_t()
            if packetLength >= 20 && (packetPtr[0] >> 4) == 4 {
                // IPv4 packet
                flow.ip_version = 4
                flow.protocol = packetPtr[9]
                // Extract ports for TCP/UDP
                if packetLength >= 28 && (flow.protocol == 6 || flow.protocol == 17) {
                    flow.src_port = UInt16(packetPtr[20]) << 8 | UInt16(packetPtr[21])
                    flow.dst_port = UInt16(packetPtr[22]) << 8 | UInt16(packetPtr[23])
                }
            }
            
            // Step 1: Privacy inspection (disabled for now)
            // Privacy guards were blocking all traffic
            
            // Step 2: Traffic classification
            if let classifier = trafficClassifier {
                var classification = traffic_classification_t()
                traffic_classifier_analyze_packet(classifier, packetPtr, packetLength, &flow, &classification)
            }
            
            // Step 3: DNS processing (if DNS packet)
            if flow.protocol == 17 && flow.dst_port == 53, let resolver = dnsResolver {
                dns_resolver_process_packet(resolver, packetPtr, packetLength, &flow.src_ip, flow.src_port)
                logger.debug("🔍 Processing DNS packet")
            }
            
            // Step 4: Forward packet to internet (for now, just pass through)
            let processedPackets = [packet]
            let protocolNumbers = [protocolNumber]
            packetFlow.writePackets(processedPackets, withProtocols: protocolNumbers)
        }
    }
    
    private func setupMetricsMonitoring() {
        logger.debug("Setting up metrics monitoring...")
        
        // Simplified metrics for component-based processing
        logger.debug("Metrics monitoring ready (privacy guards disabled)")
    }
}

// MARK: - Error Types
enum PacketTunnelError: Error, LocalizedError {
    case startFailed
    case configurationFailed
    case networkSettingsFailed
    
    var errorDescription: String? {
        switch self {
        case .startFailed:
            return "Failed to start VPN tunnel"
        case .configurationFailed:
            return "Failed to configure tunnel provider"
        case .networkSettingsFailed:
            return "Failed to apply network settings"
        }
    }
}
