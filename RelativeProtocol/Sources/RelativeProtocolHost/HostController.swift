//
//  HostController.swift
//  RelativeProtocolHost
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/27/2025.
//
//  High-level facade around `NETunnelProviderManager` that prepares, connects,
//  and observes Relative Protocol tunnel sessions for host apps.
//

import Foundation
import NetworkExtension
import OSLog
import RelativeProtocolCore

public enum RelativeProtocolHost {}

public extension RelativeProtocolHost {
    struct TunnelDescriptor: Sendable {
        public var providerBundleIdentifier: String
        public var serverAddress: String
        public var localizedDescription: String
        public var configuration: RelativeProtocol.Configuration
        public var disconnectOnSleep: Bool
        public var validateConfiguration: Bool

        public var includeAllNetworks: Bool {
            get { configuration.provider.includeAllNetworks }
            set { configuration.provider.includeAllNetworks = newValue }
        }

        public var excludeLocalNetworks: Bool {
            get { configuration.provider.excludeLocalNetworks }
            set { configuration.provider.excludeLocalNetworks = newValue }
        }

        public var excludeAPNs: Bool {
            get { configuration.provider.excludeAPNs }
            set { configuration.provider.excludeAPNs = newValue }
        }

        public init(
            providerBundleIdentifier: String,
            serverAddress: String = "RelativeProtocol",
            localizedDescription: String,
            configuration: RelativeProtocol.Configuration,
            disconnectOnSleep: Bool = false,
            validateConfiguration: Bool = false
        ) {
            self.providerBundleIdentifier = providerBundleIdentifier
            self.serverAddress = serverAddress
            self.localizedDescription = localizedDescription
            self.configuration = configuration
            self.disconnectOnSleep = disconnectOnSleep
            self.validateConfiguration = validateConfiguration
        }

        public init(
            providerBundleIdentifier: String,
            serverAddress: String = "RelativeProtocol",
            localizedDescription: String,
            configuration: RelativeProtocol.Configuration,
            includeAllNetworks: Bool = true,
            excludeLocalNetworks: Bool = false,
            excludeAPNs: Bool = false,
            disconnectOnSleep: Bool = false,
            validateConfiguration: Bool = false
        ) {
            self.init(
                providerBundleIdentifier: providerBundleIdentifier,
                serverAddress: serverAddress,
                localizedDescription: localizedDescription,
                configuration: configuration,
                disconnectOnSleep: disconnectOnSleep,
                validateConfiguration: validateConfiguration
            )
            self.includeAllNetworks = includeAllNetworks
            self.excludeLocalNetworks = excludeLocalNetworks
            self.excludeAPNs = excludeAPNs
        }
    }
}

public extension RelativeProtocolHost {
    @MainActor
    final class Controller: ObservableObject {
        public enum ControllerError: Swift.Error {
            case managerUnavailable
            case sessionUnavailable
            case tunnelNotConnected
        }

        @Published public private(set) var status: NEVPNStatus = .invalid
        @Published public private(set) var isBusy = false
        @Published public private(set) var isConfigured = false
        @Published public private(set) var lastError: String?

        public var controlChannel: RelativeProtocolHost.ControlChannel {
            RelativeProtocolHost.ControlChannel(
                managerProvider: { [weak self] () -> NETunnelProviderManager? in
                    self?.manager
                },
                preferenceLoader: { [weak self] manager in
                    guard let self else { return }
                    try await Self.loadPreferences(for: manager)
                    self.refreshStatus()
                }
            )
        }

        private var manager: NETunnelProviderManager?
        private var statusObserver: NSObjectProtocol?
        private let log = Logger(subsystem: "relative.host", category: "Controller")

        public init() {}

        deinit {
            if let statusObserver {
                NotificationCenter.default.removeObserver(statusObserver)
            }
        }

        public func prepareIfNeeded(descriptor: RelativeProtocolHost.TunnelDescriptor) async throws {
            guard manager == nil else { return }
            try await configure(descriptor: descriptor)
        }

        public func configure(descriptor: RelativeProtocolHost.TunnelDescriptor) async throws {
            guard !isBusy else { return }
            isBusy = true
            defer { isBusy = false }

            do {
                let managers = try await Self.loadManagers()
                let activeManager: NETunnelProviderManager
                if let existing = managers.first {
                    activeManager = existing
                    try await Self.loadPreferences(for: activeManager)
                } else {
                    activeManager = NETunnelProviderManager()
                }

                if descriptor.validateConfiguration {
                    _ = try? descriptor.configuration.validateOrThrow()
                }

                if let existingProto = activeManager.protocolConfiguration as? NETunnelProviderProtocol {
                    let desiredConfig = descriptor.configuration.providerConfigurationDictionary()
                    let currentConfig = existingProto.providerConfiguration as? [String: NSObject] ?? [:]
                    let currentDict = NSDictionary(dictionary: currentConfig)
                    var configChanged = !currentDict.isEqual(to: desiredConfig)
                        || existingProto.providerBundleIdentifier != descriptor.providerBundleIdentifier
                        || (existingProto.serverAddress ?? "") != descriptor.serverAddress
                        || existingProto.includeAllNetworks != descriptor.includeAllNetworks
                        || existingProto.excludeLocalNetworks != descriptor.excludeLocalNetworks
                        || existingProto.disconnectOnSleep != descriptor.disconnectOnSleep
                        || activeManager.localizedDescription != descriptor.localizedDescription

                    if #available(iOS 16.4, macOS 13.3, *) {
                        if existingProto.excludeAPNs != descriptor.excludeAPNs {
                            configChanged = true
                        }
                    } else if descriptor.excludeAPNs {
                        log.warning("excludeAPNs requested but requires iOS 16.4 / macOS 13.3 or newer")
                    }

                    if configChanged {
                        existingProto.providerBundleIdentifier = descriptor.providerBundleIdentifier
                        existingProto.serverAddress = descriptor.serverAddress
                        existingProto.includeAllNetworks = descriptor.includeAllNetworks
                        existingProto.excludeLocalNetworks = descriptor.excludeLocalNetworks
                        if #available(iOS 16.4, macOS 13.3, *) {
                            existingProto.excludeAPNs = descriptor.excludeAPNs
                        }
                        existingProto.disconnectOnSleep = descriptor.disconnectOnSleep
                        existingProto.providerConfiguration = desiredConfig
                        activeManager.protocolConfiguration = existingProto
                        activeManager.localizedDescription = descriptor.localizedDescription
                        activeManager.isEnabled = true
                        try await Self.save(activeManager)
                        try await Self.loadPreferences(for: activeManager)
                    } else if activeManager.isEnabled == false {
                        activeManager.isEnabled = true
                        try await Self.save(activeManager)
                        try await Self.loadPreferences(for: activeManager)
                    }
                } else {
                    try await apply(descriptor: descriptor, to: activeManager)
                }

                manager = activeManager
                isConfigured = true
                observeStatus(for: activeManager)
                refreshStatus()
                lastError = nil
            } catch {
                lastError = error.localizedDescription
                log.error("configure failed: \(error.localizedDescription, privacy: .public)")
                throw error
            }
        }

        public func connect() async throws {
            guard let manager else { throw ControllerError.managerUnavailable }
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                return
            default:
                break
            }

            isBusy = true
            defer { isBusy = false }

            do {
                try await Self.loadPreferences(for: manager)
                guard let session = manager.connection as? NETunnelProviderSession else {
                    throw ControllerError.sessionUnavailable
                }
                try session.startVPNTunnel()
                lastError = nil
            } catch {
                lastError = error.localizedDescription
                log.error("connect failed: \(error.localizedDescription, privacy: .public)")
                refreshStatus()
                throw error
            }
        }

        public func disconnect() {
            guard let manager else { return }
            switch manager.connection.status {
            case .disconnected, .disconnecting, .invalid:
                return
            default:
                break
            }
            manager.connection.stopVPNTunnel()
            refreshStatus()
        }

        private func apply(descriptor: RelativeProtocolHost.TunnelDescriptor, to manager: NETunnelProviderManager) async throws {
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = descriptor.providerBundleIdentifier
            proto.serverAddress = descriptor.serverAddress
        proto.includeAllNetworks = descriptor.includeAllNetworks
        proto.excludeLocalNetworks = descriptor.excludeLocalNetworks
        if #available(iOS 16.4, macOS 13.3, *) {
            proto.excludeAPNs = descriptor.excludeAPNs
        } else if descriptor.excludeAPNs {
            log.warning("excludeAPNs requested but requires iOS 16.4 / macOS 13.3 or newer")
        }
            proto.disconnectOnSleep = descriptor.disconnectOnSleep
            proto.providerConfiguration = descriptor.configuration.providerConfigurationDictionary()

            manager.protocolConfiguration = proto
            manager.localizedDescription = descriptor.localizedDescription
            manager.isEnabled = true

            try await Self.save(manager)
            try await Self.loadPreferences(for: manager)
        }

        private func observeStatus(for manager: NETunnelProviderManager) {
            if let statusObserver {
                NotificationCenter.default.removeObserver(statusObserver)
                self.statusObserver = nil
            }
            statusObserver = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange,
                object: manager.connection,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.refreshStatus()
                }
            }
            refreshStatus()
        }

        private func refreshStatus() {
            guard let manager else {
                status = .invalid
                return
            }
            status = manager.connection.status
        }
    }
}

// MARK: - Preference helpers

extension RelativeProtocolHost.Controller {
    static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    static func loadPreferences(for manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    static func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}
