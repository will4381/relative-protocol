// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "RelativeProtocol",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "RelativeProtocol", 
            targets: ["RelativeProtocol"]
        ),
    ],
    targets: [
        .target(
            name: "RelativeProtocol",
            dependencies: [],
            path: "src",
            sources: [
                "core/logging.c",
                "packet/buffer_manager.c", 
                "packet/tunnel_provider.mm",
                "tcp_udp/connection_manager.c",
                "dns/resolver.c",
                "nat64/translator.c",
                "ios_vpn.c",
                "metrics/ring_buffer.c"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("../include"),
                .headerSearchPath("../include/core"),
                .headerSearchPath("../include/packet"),
                .headerSearchPath("../include/tcp_udp"),
                .headerSearchPath("../include/dns"),
                .headerSearchPath("../include/nat64"),
                .headerSearchPath("../include/metrics"),
                .define("TARGET_OS_IOS"),
                .unsafeFlags(["-Wall", "-Wextra"], .when(configuration: .debug))
            ],
            linkerSettings: [
                .linkedFramework("CoreTelephony", .when(platforms: [.iOS])),
                .linkedFramework("NetworkExtension", .when(platforms: [.iOS])),
                .linkedFramework("Network", .when(platforms: [.iOS])),
                .linkedLibrary("pthread")
            ]
        )
    ],
    cLanguageStandard: .c11,
    cxxLanguageStandard: .cxx17
)