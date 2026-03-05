import DataplaneFFICBridge
import Foundation
import Observability

private final class CallbackBox {
    let callbacks: DataplaneCallbacks

    init(callbacks: DataplaneCallbacks) {
        self.callbacks = callbacks
    }
}

private func bridgeLogCallback(message: UnsafePointer<CChar>?, userCtx: UnsafeMutableRawPointer?) {
    guard let userCtx else {
        return
    }
    let box = Unmanaged<CallbackBox>.fromOpaque(userCtx).takeUnretainedValue()
    let value = message.map { String(cString: $0) } ?? ""
    box.callbacks.onLog(value)
}

private func bridgeStateCallback(state: UInt32, userCtx: UnsafeMutableRawPointer?) {
    guard let userCtx else {
        return
    }
    let box = Unmanaged<CallbackBox>.fromOpaque(userCtx).takeUnretainedValue()
    box.callbacks.onState(DataplaneState(raw: state))
}

/// Actor wrapper around the C dataplane handle lifecycle and version guard.
public actor DataplaneHandle {
    private var rawHandle: OpaquePointer?
    private let callbackToken: Unmanaged<CallbackBox>
    private let logger: StructuredLogger

    /// Validates runtime dataplane API/ABI compatibility before creating a handle.
    /// - Parameter expected: Expected API/ABI contract version.
    /// - Throws: `DataplaneError.versionMismatch` when runtime versions do not match.
    public static func validateCompatibility(expected: DataplaneVersion = .current) throws {
        let version = rp_dp_get_version()
        let actual = DataplaneVersion(apiVersion: version.api_version, abiVersion: version.abi_version)
        guard actual == expected else {
            throw DataplaneError.versionMismatch(expected: expected, actual: actual)
        }
    }

    /// Creates a dataplane handle and installs Swift callback bridges.
    /// - Parameters:
    ///   - configJSON: Dataplane configuration payload forwarded to the C bridge.
    ///   - callbacks: Swift callback hooks invoked from dataplane callback queue.
    ///   - expectedVersion: Expected API/ABI version contract.
    ///   - logger: Structured logger used for lifecycle failures.
    /// - Throws: Version mismatch or create failure errors.
    public init(
        configJSON: String,
        callbacks: DataplaneCallbacks = .noop,
        expectedVersion: DataplaneVersion = .current,
        logger: StructuredLogger
    ) throws {
        try Self.validateCompatibility(expected: expectedVersion)

        self.logger = logger
        let callbackBox = CallbackBox(callbacks: callbacks)
        self.callbackToken = Unmanaged.passRetained(callbackBox)

        var bridgeCallbacks = rp_dp_callbacks_t(
            on_log: bridgeLogCallback,
            on_state: bridgeStateCallback
        )
        let callbackToken = self.callbackToken

        let handle = configJSON.withCString { rawCString in
            rp_dp_create(rawCString, &bridgeCallbacks, callbackToken.toOpaque())
        }

        guard let handle else {
            self.callbackToken.release()
            throw DataplaneError.createFailed
        }

        self.rawHandle = handle
    }

    deinit {
        if let rawHandle {
            rp_dp_destroy(rawHandle)
        }
        callbackToken.release()
    }

    /// Starts dataplane processing against the provided tunnel file descriptor.
    /// - Parameter tunFD: Tunnel descriptor passed to the native dataplane bridge.
    /// - Throws: `DataplaneError.destroyed` or `DataplaneError.startFailed`.
    public func start(tunFD: Int32) async throws {
        guard let rawHandle else {
            throw DataplaneError.destroyed
        }
        let result = rp_dp_start(rawHandle, tunFD)
        guard result == 0 else {
            await logger.log(
                level: .error,
                phase: .relay,
                category: .dataplane,
                component: "DataplaneHandle",
                event: "start-failed",
                errorCode: String(result),
                message: "Failed to start dataplane"
            )
            throw DataplaneError.startFailed(code: result)
        }
    }

    /// Stops dataplane processing.
    /// - Throws: `DataplaneError.destroyed` or `DataplaneError.stopFailed`.
    public func stop() async throws {
        guard let rawHandle else {
            throw DataplaneError.destroyed
        }
        let result = rp_dp_stop(rawHandle)
        guard result == 0 else {
            throw DataplaneError.stopFailed(code: result)
        }
    }

    /// Reads dataplane packet/byte counters.
    /// - Returns: Current dataplane statistics snapshot.
    /// - Throws: `DataplaneError.destroyed` or `DataplaneError.statsFailed`.
    public func stats() throws -> DataplaneStats {
        guard let rawHandle else {
            throw DataplaneError.destroyed
        }
        var native = rp_dp_stats_t()
        let result = rp_dp_get_stats(rawHandle, &native)
        guard result == 0 else {
            throw DataplaneError.statsFailed(code: result)
        }
        return DataplaneStats(
            packetsIn: native.packets_in,
            packetsOut: native.packets_out,
            bytesIn: native.bytes_in,
            bytesOut: native.bytes_out
        )
    }

    /// Idempotently destroys the underlying native dataplane handle.
    public func destroy() {
        guard let rawHandle else {
            return
        }
        rp_dp_destroy(rawHandle)
        self.rawHandle = nil
    }
}
