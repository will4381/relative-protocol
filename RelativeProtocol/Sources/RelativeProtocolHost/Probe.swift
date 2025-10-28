//
//  Probe.swift
//  RelativeProtocolHost
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/27/2025.
//
//  Supplies lightweight reachability probes (TCP/HTTPS) that the host app can
//  invoke for quick diagnostics without hand-rolling NWConnection plumbing.
//

import Foundation
import Network

public extension RelativeProtocolHost {
    struct ProbeReport: Sendable {
        public var success: Bool
        public var message: String
        public var duration: TimeInterval?

        public init(success: Bool, message: String, duration: TimeInterval?) {
            self.success = success
            self.message = message
            self.duration = duration
        }
    }

    enum Probe {
        public static func tcp(
            host: String,
            port: UInt16,
            timeout: TimeInterval = 5.0
        ) async -> ProbeReport {
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                return ProbeReport(success: false, message: "invalid port", duration: nil)
            }
            let start = Date()
            let queue = DispatchQueue(label: "relative.host.probe.tcp")
            return await withCheckedContinuation { continuation in
                let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
                params.allowLocalEndpointReuse = true
                params.prohibitedInterfaceTypes = [.loopback, .other]

                let connection = NWConnection(host: .init(host), port: nwPort, using: params)
                let state = ProbeState()
                let finish: @Sendable (Bool, String) -> Void = { success, message in
                    state.lock.lock()
                    defer { state.lock.unlock() }
                    guard !state.finished else { return }
                    state.finished = true
                    connection.cancel()
                    let duration = success ? Date().timeIntervalSince(start) : nil
                    continuation.resume(returning: ProbeReport(success: success, message: message, duration: duration))
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        finish(true, "ok")
                    case .waiting(let error):
                        finish(false, "waiting: \(error.localizedDescription)")
                    case .failed(let error):
                        finish(false, "error: \(error.localizedDescription)")
                    case .cancelled:
                        finish(false, "cancelled")
                    default:
                        break
                    }
                }

                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) {
                    finish(false, "timeout")
                }
            }
        }

        public static func https(
            url: URL,
            timeout: TimeInterval = 10.0
        ) async -> ProbeReport {
            let start = Date()
            var request = URLRequest(url: url)
            request.timeoutInterval = timeout
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

            do {
                let (_, response) = try await URLSession.shared.data(for: request)
                let duration = Date().timeIntervalSince(start)
                if let http = response as? HTTPURLResponse {
                    return ProbeReport(success: true, message: "HTTP \(http.statusCode)", duration: duration)
                }
                return ProbeReport(success: true, message: "non-HTTP response", duration: duration)
            } catch {
                return ProbeReport(success: false, message: "error: \(error.localizedDescription)", duration: Date().timeIntervalSince(start))
            }
        }
    }
}

private final class ProbeState: @unchecked Sendable {
    let lock = NSLock()
    var finished = false
}
