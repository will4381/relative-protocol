import NetworkExtension
import RelativeProtocol
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = Logger(subsystem: "relative-companies.Scroll.ScrollMonitorExtension", category: "PacketTunnelProvider")
    private var vpnHandle: vpn_handle_t? = nil
    private var tunnelProvider: OpaquePointer?
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting packet tunnel with RelativeProtocol...")
        
        // Configure RelativeProtocol VPN settings
        var config = vpn_config_t()
        
        // Set log level (keep minimal for privacy)
        config.log_level = strdup("error")
        
        // Configure tunnel settings
        config.tunnel_mtu = 1500
        config.enable_nat64 = true
        config.enable_dns_leak_protection = true
        
        // Start the RelativeProtocol VPN engine
        let result = vpn_start_comprehensive(&config)
        guard result.status == 0 else {
            logger.error("Failed to start RelativeProtocol VPN engine: \(result.status)")
            completionHandler(PacketTunnelError.startFailed)
            return
        }
        
        vpnHandle = result.handle
        logger.info("RelativeProtocol VPN engine started successfully")
        
        // Create and configure tunnel provider for packet flow
        tunnelProvider = tunnel_provider_create()
        guard let tunnelProvider = tunnelProvider else {
            logger.error("Failed to create tunnel provider")
            completionHandler(PacketTunnelError.configurationFailed)
            return
        }
        
        // Configure packet flow with the tunnel provider
        tunnel_provider_configure_packet_flow(tunnelProvider, packetFlow)
        
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
            
            // Set up metrics monitoring if needed
            self?.setupMetricsMonitoring()
            
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping packet tunnel...")
        
        // Clean up tunnel provider
        if let tunnelProvider = tunnelProvider {
            tunnel_provider_destroy(tunnelProvider)
            self.tunnelProvider = nil
        }
        
        // Stop RelativeProtocol VPN engine
        if let handle = vpnHandle {
            vpn_stop_comprehensive(handle)
            vpnHandle = nil
            logger.info("RelativeProtocol VPN engine stopped")
        }
        
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        logger.debug("Received app message: \(messageData.count) bytes")
        
        // Handle messages from the main app if needed
        // For now, just acknowledge receipt
        completionHandler?(Data())
    }
    
    private func setupMetricsMonitoring() {
        logger.debug("Setting up metrics monitoring...")
        
        // Set up metrics callback to monitor VPN performance
        vpn_set_metrics_callback({ metrics, userData in
            guard let metrics = metrics?.pointee else { return }
            
            // Log metrics periodically (consider privacy implications)
            let logger = Logger(subsystem: "relative-companies.Scroll.ScrollMonitorExtension", category: "Metrics")
            logger.debug("VPN Metrics - Bytes in: \(metrics.bytes_in), Bytes out: \(metrics.bytes_out)")
            
        }, nil)
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
