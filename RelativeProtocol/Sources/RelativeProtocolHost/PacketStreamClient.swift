// Created by Will Kusch 1/23/26
// Property of Relative Companies Inc. See LICENSE for more info.
// Code is not to be reproduced or used in any commercial project, free or paid.
import Foundation
import RelativeProtocolCore

public struct PacketStreamClient {
    private let reader: PacketSampleStreamReader

    public init(appGroupID: String) {
        reader = PacketSampleStreamReader(appGroupID: appGroupID)
    }

    public func readAll() -> [PacketSample] {
        reader.readAll()
    }

    public func readNew(sinceOffset offset: UInt64) -> (samples: [PacketSample], nextOffset: UInt64) {
        reader.readNew(sinceOffset: offset)
    }
}
