//
//  ControlChannel.swift
//  RelativeProtocolHost
//
//  Created by Codex on 10/27/25.
//

import Foundation
import NetworkExtension

public extension RelativeProtocolHost {
    @MainActor
    struct ControlChannel {
        public enum Error: Swift.Error {
            case tunnelUnavailable
            case tunnelNotConnected
            case sessionUnavailable
            case noResponse
            case encodingFailed(Swift.Error)
            case decodingFailed(Swift.Error)
        }

        private let managerProvider: @MainActor () -> NETunnelProviderManager?
        private let preferenceLoader: @MainActor (NETunnelProviderManager) async throws -> Void

        init(
            managerProvider: @escaping @MainActor () -> NETunnelProviderManager?,
            preferenceLoader: @escaping @MainActor (NETunnelProviderManager) async throws -> Void
        ) {
            self.managerProvider = managerProvider
            self.preferenceLoader = preferenceLoader
        }

        @discardableResult
        public func send<Request: Encodable>(
            _ request: Request,
            encoder: JSONEncoder = JSONEncoder()
        ) async throws -> Data? {
            do {
                let payload = try encoder.encode(request)
                return try await sendRaw(payload)
            } catch {
                throw Error.encodingFailed(error)
            }
        }

        public func send<Request: Encodable, Response: Decodable>(
            _ request: Request,
            expecting type: Response.Type,
            encoder: JSONEncoder = JSONEncoder(),
            decoder: JSONDecoder = JSONDecoder()
        ) async throws -> Response {
            let responseData: Data? = try await send(request, encoder: encoder)
            guard let responseData else {
                throw Error.noResponse
            }
            do {
                return try decoder.decode(Response.self, from: responseData)
            } catch {
                throw Error.decodingFailed(error)
            }
        }

        @discardableResult
        public func sendRaw(_ data: Data) async throws -> Data? {
            guard let manager = managerProvider() else {
                throw Error.tunnelUnavailable
            }
            try await preferenceLoader(manager)
            guard manager.connection.status == .connected else {
                throw Error.tunnelNotConnected
            }
            guard let session = manager.connection as? NETunnelProviderSession else {
                throw Error.sessionUnavailable
            }
            return try await Self.send(data, via: session)
        }
    }
}

private extension RelativeProtocolHost.ControlChannel {
    static func send(_ data: Data, via session: NETunnelProviderSession) async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
