// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RelativeProtocol",
    platforms: [
        .iOS(.v15),
        .macOS(.v10_14)
    ],
    products: [
        .library(
            name: "RelativeProtocol", 
            targets: ["RelativeProtocol"]
        ),
        .library(
            name: "RelativeProtocolNE",
            targets: ["RelativeProtocolNE"]
        ),
    ],
    targets: [
        // Pure C lwIP glue
        .target(
            name: "RelativeProtocolC",
            path: ".",
            sources: [
                // Glue
                "Sources/RelativeProtocolC/rlwip_glue.c",
                // Minimal lwIP object sources needed for compile/link
                "third_party/lwip/lwip-src/src/core/init.c",
                "third_party/lwip/lwip-src/src/core/ip.c",
                "third_party/lwip/lwip-src/src/core/mem.c",
                "third_party/lwip/lwip-src/src/core/memp.c",
                "third_party/lwip/lwip-src/src/core/def.c",
                "third_party/lwip/lwip-src/src/core/pbuf.c",
                "third_party/lwip/lwip-src/src/core/netif.c",
                "third_party/lwip/lwip-src/src/core/raw.c",
                "third_party/lwip/lwip-src/src/core/stats.c",
                "third_party/lwip/lwip-src/src/core/sys.c",
                "third_party/lwip/lwip-src/src/core/timeouts.c",
                "third_party/lwip/lwip-src/src/core/inet_chksum.c",
                "third_party/lwip/lwip-src/src/core/udp.c",
                "third_party/lwip/lwip-src/src/core/tcp.c",
                "third_party/lwip/lwip-src/src/core/tcp_in.c",
                "third_party/lwip/lwip-src/src/core/tcp_out.c",
                "third_party/lwip/lwip-src/src/core/ipv4/autoip.c",
                "third_party/lwip/lwip-src/src/core/ipv4/icmp.c",
                "third_party/lwip/lwip-src/src/core/ipv4/igmp.c",
                "third_party/lwip/lwip-src/src/core/ipv4/ip4.c",
                "third_party/lwip/lwip-src/src/core/ipv4/ip4_addr.c",
                "third_party/lwip/lwip-src/src/core/ipv4/ip4_frag.c",
                "third_party/lwip/lwip-src/src/core/ipv6/ip6.c",
                "third_party/lwip/lwip-src/src/core/ipv6/ip6_addr.c",
                "third_party/lwip/lwip-src/src/core/ipv6/ip6_frag.c",
                "third_party/lwip/lwip-src/src/core/ipv6/icmp6.c",
                "third_party/lwip/lwip-src/src/core/ipv6/nd6.c",
                "third_party/lwip/lwip-src/src/core/ipv6/mld6.c",
                "third_party/lwip/lwip-src/src/core/ipv6/ethip6.c",
                // Our port files
                "third_party/lwip/port/relative/sys_arch.c",
                "third_party/lwip/port/relative/netif_tunif.c",
                "third_party/lwip/port/relative/netif_proxynetif.c",
                // Netif helpers (ARP disabled in lwipopts.h, so no etharp)
                "third_party/lwip/lwip-src/src/netif/ethernet.c"
            ],
            publicHeadersPath: "",
            cSettings: [
                .headerSearchPath("third_party/lwip/port/relative"),
                .headerSearchPath("third_party/lwip/lwip-src/src/include"),
                .headerSearchPath("third_party/lwip/lwip-src/src/include/lwip"),
                .headerSearchPath("third_party/lwip/port/relative/arch"),
                .define("RELATIVE_WITH_LWIP"),
                .unsafeFlags(["-Wall", "-Wextra"], .when(configuration: .debug))
            ]
        ),
        // Swift wrapper target
        .target(
            name: "RelativeProtocol",
            dependencies: ["RelativeProtocolC"],
            path: "Sources/RelativeProtocol",
            exclude: [],
            resources: [],
            linkerSettings: [
                .linkedFramework("CoreTelephony", .when(platforms: [.iOS])),
                .linkedFramework("Network", .when(platforms: [.iOS, .macOS]))
            ]
        ),
        // iOS-only glue that wires NE provider into the core engine
        .target(
            name: "RelativeProtocolNE",
            dependencies: [
                .target(name: "RelativeProtocol")
            ],
            path: "Sources/RelativeProtocolNE",
            exclude: [],
            resources: [],
            linkerSettings: [
                .linkedFramework("NetworkExtension", .when(platforms: [.iOS])),
                .linkedFramework("Network", .when(platforms: [.iOS]))
            ]
        ),
        .testTarget(
            name: "RelativeProtocolTests",
            dependencies: ["RelativeProtocol"],
            path: "Tests/RelativeProtocolTests"
        )
    ],
    cLanguageStandard: .c11,
    cxxLanguageStandard: .cxx17
)