// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "RelativeProtocol",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "RelativeProtocol",
            targets: ["RelativeProtocol"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "RelativeProtocol",
            dependencies: [],
            path: ".",
            sources: [
                "src/api",
                "src/core", 
                "src/packet",
                "src/tcp_udp",
                "src/socket_bridge",
                "src/dns",
                "src/metrics",
                "src/nat64",
                "src/mtu",
                "src/reachability",
                "src/classifier",
                "src/privacy",
                "src/crash"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .define("ENABLE_LOGGING", to: "0"),
                .define("ENABLE_SECURITY_FEATURES", to: "1"),
                .define("TARGET_OS_IOS", to: "1"),
                .headerSearchPath("include"),
                .headerSearchPath("third_party/lwip/src/include"),
                .unsafeFlags(["-fno-objc-arc"]),
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
                .linkedFramework("Foundation")
            ]
        ),
        .testTarget(
            name: "RelativeProtocolTests",
            dependencies: ["RelativeProtocol"],
            path: "tests",
            sources: ["unit", "integration"],
            cxxSettings: [
                .headerSearchPath("../include"),
                .define("GTEST_HAS_RTTI", to: "0")
            ]
        ),
    ],
    cLanguageStandard: .c11,
    cxxLanguageStandard: .cxx17
)