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
        .binaryTarget(
            name: "Tun2SocksBinary",
            path: "Binary/Tun2Socks.xcframework"
        ),
        .target(
            name: "RelativeProtocolCore",
            dependencies: [],
            path: "Sources/RelativeProtocolCore"
        ),
        .target(
            name: "RelativeProtocolTunnel",
            dependencies: ["RelativeProtocolCore", "Tun2SocksBinary"],
            path: "Sources/RelativeProtocolTunnel",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Network")
            ]
        ),
        .testTarget(
            name: "RelativeProtocolPerformanceTests",
            dependencies: ["RelativeProtocolCore", "RelativeProtocolTunnel"],
            path: "Tests/RelativeProtocolPerformanceTests"
        )
    ]
)
