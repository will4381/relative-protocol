import Foundation

public enum RelativeProtocol {}

public extension RelativeProtocol {
    struct Configuration: Codable, Equatable, Sendable {
        private enum Keys {
            static let storageKey = "relative_protocol_configuration"
        }

        public var serverAddress: String
        public var interface: Interface
        public var dns: DNS
        public var routes: [Route]
        public var mtu: Int
        public var packetPoolBytes: Int
        public var perFlowBufferBytes: Int

        public init(
            serverAddress: String = "10.0.0.1",
            interface: Interface = .default,
            dns: DNS = .init(servers: ["1.1.1.1"], searchDomains: []),
            routes: [Route] = [.defaultRoute],
            mtu: Int = 1400,
            packetPoolBytes: Int = 2 * 1_048_576,
            perFlowBufferBytes: Int = 256 * 1_024
        ) {
            self.serverAddress = serverAddress
            self.interface = interface
            self.dns = dns
            self.routes = routes.isEmpty ? [.defaultRoute] : routes
            self.mtu = max(576, min(mtu, 9000))
            self.packetPoolBytes = max(packetPoolBytes, 512 * 1024)
            self.perFlowBufferBytes = max(perFlowBufferBytes, 64 * 1024)
        }

        public static let `default` = Configuration()

        public func providerConfigurationDictionary() -> [String: Any] {
            guard let encoded = try? JSONEncoder().encode(self) else {
                return [:]
            }
            return [Keys.storageKey: encoded]
        }

        public static func load(from dictionary: [String: Any]?) -> Configuration {
            guard
                let raw = dictionary?[Keys.storageKey] as? Data,
                let decoded = try? JSONDecoder().decode(Configuration.self, from: raw)
            else {
                return .default
            }
            return decoded
        }
    }
}

public extension RelativeProtocol.Configuration {
    struct Interface: Codable, Equatable, Sendable {
        public var address: String
        public var subnetMask: String

        public init(address: String, subnetMask: String) {
            self.address = address
            self.subnetMask = subnetMask
        }

        public static let `default` = Interface(address: "10.0.0.2", subnetMask: "255.255.255.0")
    }

    struct DNS: Codable, Equatable, Sendable {
        public var servers: [String]
        public var searchDomains: [String]

        public init(servers: [String], searchDomains: [String]) {
            self.servers = servers
            self.searchDomains = searchDomains
        }
    }

    struct Route: Codable, Equatable, Identifiable, Sendable {
        public var id: UUID
        public var destinationAddress: String
        public var subnetMask: String

        public init(id: UUID = UUID(), destinationAddress: String, subnetMask: String) {
            self.id = id
            self.destinationAddress = destinationAddress
            self.subnetMask = subnetMask
        }

        public var isDefault: Bool {
            destinationAddress == "0.0.0.0" && subnetMask == "0.0.0.0"
        }

        public static var defaultRoute: Route {
            Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
        }
    }
}
