// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "RelativeProtocol",
    platforms: [
        .iOS(.v15),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RelativeProtocolCore", targets: ["RelativeProtocolCore"]),
        .library(name: "RelativeProtocolTunnel", targets: ["RelativeProtocolTunnel"]),
    ],
    dependencies: [],
    targets: [
        // Vendored binary (gomobile) relative to repo root
        .binaryTarget(
            name: "Tun2SocksBinary",
            path: "RelativeProtocol/Binary/Tun2Socks.xcframework"
        ),
        .target(
            name: "RelativeProtocolCore",
            dependencies: [],
            path: "RelativeProtocol/Sources/RelativeProtocolCore"
        ),
        .target(
            name: "RelativeProtocolTunnel",
            dependencies: ["RelativeProtocolCore", "Tun2SocksBinary"],
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
        )
    ]
)

