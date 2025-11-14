import Foundation
import RelativeProtocolCore

public struct TunnelDescriptor: Equatable, Sendable {
    public var localizedDescription: String
    public var providerBundleIdentifier: String
    public var configuration: RelativeProtocol.Configuration

    public init(
        localizedDescription: String,
        providerBundleIdentifier: String,
        configuration: RelativeProtocol.Configuration
    ) {
        self.localizedDescription = localizedDescription
        self.providerBundleIdentifier = providerBundleIdentifier
        self.configuration = configuration
    }
}
