// swift-tools-version: 5.9

import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let fileManager = FileManager.default

let leafCandidatePaths: [String] = [
    environment["LEAF_XCFRAMEWORK_PATH"],
    "RelativeProtocol/Binary/Leaf.xcframework",
    "Build/Leaf/Leaf.xcframework"
].compactMap { $0 }

let leafLocalPath = leafCandidatePaths.first { path in
    fileManager.fileExists(atPath: path)
}

guard let leafBinaryPath = leafLocalPath else {
    fatalError("""
    Leaf xcframework not found. Run ./Scripts/build.sh to generate RelativeProtocol/Binary/Leaf.xcframework \
    or set LEAF_XCFRAMEWORK_PATH to a valid location before resolving the package.
    """)
}

let leafBinaryTarget: Target = .binaryTarget(
    name: "LeafBinary",
    path: leafBinaryPath
)

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
