// swift-tools-version: 5.9

import PackageDescription

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
        // Vendored binary (gomobile) relative to repo root
        .binaryTarget(
            name: "Tun2SocksBinary",
            path: "RelativeProtocol/Binary/Tun2Socks.xcframework"
        ),
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
                "Tun2SocksBinary",
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
