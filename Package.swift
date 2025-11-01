// swift-tools-version: 5.9

import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let fileManager = FileManager.default

let leafCandidatePaths: [String] = [
    environment["LEAF_XCFRAMEWORK_PATH"],
    "RelativeProtocol/Binary/Leaf.xcframework"
].compactMap { $0 }

let leafLocalPath = leafCandidatePaths.first { path in
    fileManager.fileExists(atPath: path)
}

let leafArchiveURL = environment["LEAF_XCFRAMEWORK_URL"]
    ?? "https://github.com/will4381/relative-protocol/releases/download/vNEXT/Leaf.xcframework.zip"

let leafArchiveChecksum = environment["LEAF_XCFRAMEWORK_CHECKSUM"]
    ?? "56dde7c3c2da00280d91fbefe6699b05944de9d380e4d379e60538b872f93162"

let leafBinaryTarget: Target
if let localPath = leafLocalPath {
    leafBinaryTarget = .binaryTarget(
        name: "LeafBinary",
        path: localPath
    )
} else {
    leafBinaryTarget = .binaryTarget(
        name: "LeafBinary",
        url: leafArchiveURL,
        checksum: leafArchiveChecksum
    )
}

let package = Package(
    name: "RelativeProtocol",
    platforms: [
        .iOS(.v16),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RelativeProtocolCore", targets: ["RelativeProtocolCore"]),
        .library(name: "RelativeProtocolTunnel", targets: ["RelativeProtocolTunnel"]),
        .library(name: "RelativeProtocolHost", targets: ["RelativeProtocolHost"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-async-dns-resolver.git", from: "0.4.0"),
        .package(url: "https://github.com/apple/swift-async-algorithms.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.0.5")
    ],
    targets: [
        leafBinaryTarget,
        .target(
            name: "RelativeProtocolHost",
            dependencies: [
                "RelativeProtocolCore"
            ],
            path: "RelativeProtocol/Sources/RelativeProtocolHost",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Network")
            ]
        ),
        .target(
            name: "RelativeProtocolCore",
            dependencies: [
                .product(name: "Collections", package: "swift-collections")
            ],
            path: "RelativeProtocol/Sources/RelativeProtocolCore"
        ),
        .target(
            name: "RelativeProtocolTunnel",
            dependencies: [
                "RelativeProtocolCore",
                "LeafBinary",
                .product(name: "AsyncDNSResolver", package: "swift-async-dns-resolver"),
                .product(name: "AsyncAlgorithms", package: "swift-async-algorithms"),
                .product(name: "Collections", package: "swift-collections")
            ],
            path: "RelativeProtocol/Sources/RelativeProtocolTunnel",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Network")
            ]
        ),
        .testTarget(
            name: "RelativeProtocolPerformanceTests",
            dependencies: ["RelativeProtocolCore", "RelativeProtocolTunnel"],
            path: "RelativeProtocol/Tests/RelativeProtocolPerformanceTests"
        ),
        .testTarget(
            name: "RelativeProtocolTunnelTests",
            dependencies: [
                "RelativeProtocolCore",
                "RelativeProtocolTunnel"
            ],
            path: "RelativeProtocol/Tests/RelativeProtocolTunnelTests"
        )
    ]
)
