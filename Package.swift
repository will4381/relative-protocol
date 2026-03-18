// swift-tools-version: 5.9
import PackageDescription

let strictSwiftSettings: [SwiftSetting] = [
    .unsafeFlags(["-strict-concurrency=complete"]),
    .unsafeFlags(["-warnings-as-errors"], .when(platforms: [.macOS]))
]

let strictCSettings: [CSetting] = [
    .unsafeFlags(["-Wall", "-Wextra", "-Werror", "-Wpedantic"])
]

let package = Package(
    name: "VPNBridgeTunnel",
    platforms: [
        .iOS("18.0"),
        .macOS(.v14)
    ],
    products: [
        .library(name: "DataplaneFFI", targets: ["DataplaneFFI"]),
        .library(name: "TunnelRuntime", targets: ["TunnelRuntime"]),
        .library(name: "PacketRelay", targets: ["PacketRelay"]),
        .library(name: "Analytics", targets: ["Analytics"]),
        .library(name: "Observability", targets: ["Observability"]),
        .library(name: "TunnelControl", targets: ["TunnelControl"]),
        .library(name: "HostClient", targets: ["HostClient"]),
        .executable(name: "HarnessLocal", targets: ["HarnessLocal"])
    ],
    targets: [
        .target(
            name: "HevSocks5Tunnel",
            path: "ThirdParty/hev-socks5-tunnel",
            exclude: [
                ".clang-format",
                ".dockerignore",
                ".github",
                ".git",
                ".gitignore",
                ".gitmodules",
                "Android.mk",
                "Application.mk",
                "Dockerfile",
                "Makefile",
                "README.md",
                "build-apple.sh",
                "build.mk",
                "conf",
                "docker",
                "module.modulemap",
                "third-part/hev-task-system/configs.mk",
                "third-part/hev-task-system/apps",
                "third-part/hev-task-system/tests",
                "third-part/hev-task-system/src/kern/io/hev-task-io-reactor-epoll.c",
                "third-part/hev-task-system/src/kern/io/hev-task-io-reactor-iocp.c",
                "third-part/hev-task-system/src/lib/list/hev-list.c",
                "third-part/hev-task-system/src/lib/rbtree/hev-rbtree.c",
                "third-part/hev-task-system/src/arch/arc",
                "third-part/hev-task-system/src/arch/loong",
                "third-part/hev-task-system/src/arch/m68k",
                "third-part/hev-task-system/src/arch/microblaze",
                "third-part/hev-task-system/src/arch/mips",
                "third-part/hev-task-system/src/arch/openrisc",
                "third-part/hev-task-system/src/arch/ppc",
                "third-part/hev-task-system/src/arch/riscv",
                "third-part/hev-task-system/src/arch/s390",
                "third-part/hev-task-system/src/arch/sh",
                "third-part/hev-task-system/src/arch/sw64",
                "third-part/hev-task-system/src/arch/x86",
                "third-part/hev-task-system/src/arch/arm/hev-task-execute-arm.s",
                "third-part/hev-task-system/src/arch/arm/hev-task-execute-aarch64.s",
                "third-part/lwip/.git",
                "third-part/lwip/src/netif",
                "third-part/lwip/src/ports/unix",
                "third-part/lwip/src/ports/win32",
                "third-part/yaml/.git",
                "third-part/yaml/.gitlab-ci.yml",
                "third-part/yaml/configs.mk",
                "src/hev-jni.c",
                "src/hev-tunnel-linux.c",
                "src/hev-tunnel-freebsd.c",
                "src/hev-tunnel-netbsd.c",
                "src/hev-tunnel-windows.c",
                "src/misc/hev-wintun.c"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .define("ENABLE_LIBRARY"),
                .define("ENABLE_STACK_OVERFLOW_DETECTION"),
                .define("ENABLE_MEMALLOC_SLICE"),
                .define("ENABLE_IO_SPLICE_SYSCALL"),
                .define("CONFIG_STACK_BACKEND", to: "STACK_MMAP"),
                .define("CONFIG_STACK_OVERFLOW_DETECTION", to: "1"),
                .define("CONFIG_MEMALLOC_SLICE_ALIGN", to: "64"),
                .define("CONFIG_MEMALLOC_SLICE_MAX_SIZE", to: "4096"),
                .define("CONFIG_MEMALLOC_SLICE_MAX_COUNT", to: "1000"),
                .define("CONFIG_SCHED_CLOCK", to: "CLOCK_NONE"),
                .define("YAML_VERSION_MAJOR", to: "0"),
                .define("YAML_VERSION_MINOR", to: "2"),
                .define("YAML_VERSION_PATCH", to: "5"),
                .define("YAML_VERSION_STRING", to: "\"0.2.5\""),
                .headerSearchPath("src"),
                .headerSearchPath("src/core/include"),
                .headerSearchPath("src/misc"),
                .headerSearchPath("third-part/hev-task-system/include"),
                .headerSearchPath("third-part/hev-task-system/src"),
                .headerSearchPath("third-part/lwip/src/include"),
                .headerSearchPath("third-part/lwip/src/ports/include"),
                .headerSearchPath("third-part/yaml/include"),
                .unsafeFlags(["-fno-modules"])
            ]
        ),
        .target(
            name: "DataplaneFFICBridge",
            dependencies: ["HevSocks5Tunnel"],
            path: "Sources/DataplaneFFI/Bridge",
            publicHeadersPath: "include",
            cSettings: strictCSettings
        ),
        .target(
            name: "PacketIntelligenceCore",
            path: "Sources/PacketIntelligenceCore",
            publicHeadersPath: "include",
            cSettings: strictCSettings
        ),
        .target(
            name: "Observability",
            path: "Sources/Observability",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "DataplaneFFI",
            dependencies: ["DataplaneFFICBridge", "Observability"],
            path: "Sources/DataplaneFFI",
            exclude: ["Bridge"],
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "TunnelRuntime",
            dependencies: ["DataplaneFFI", "Observability"],
            path: "Sources/TunnelRuntime",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "PacketRelay",
            dependencies: ["Observability", "TunnelRuntime"],
            path: "Sources/PacketRelay",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "Analytics",
            dependencies: ["Observability", "PacketIntelligenceCore", "TunnelRuntime"],
            path: "Sources/Analytics",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "HostClient",
            dependencies: ["Analytics"],
            path: "Sources/HostClient",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "TunnelControl",
            dependencies: ["Analytics", "Observability", "PacketRelay", "TunnelRuntime"],
            path: "Sources/TunnelControl",
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "HarnessLocal",
            dependencies: ["Analytics", "Observability", "PacketRelay", "TunnelRuntime"],
            path: "Sources/HarnessLocal",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "DataplaneFFITests",
            dependencies: ["DataplaneFFI"],
            path: "Tests/DataplaneFFITests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "TunnelRuntimeTests",
            dependencies: ["TunnelRuntime", "Analytics", "Observability"],
            path: "Tests/TunnelRuntimeTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "AnalyticsTests",
            dependencies: ["Analytics", "Observability", "TunnelRuntime"],
            path: "Tests/AnalyticsTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "ObservabilityTests",
            dependencies: ["Observability"],
            path: "Tests/ObservabilityTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "PacketRelayTests",
            dependencies: ["PacketRelay", "Observability"],
            path: "Tests/PacketRelayTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "HarnessLocalTests",
            dependencies: ["HarnessLocal", "Analytics", "TunnelRuntime"],
            path: "Tests/HarnessLocalTests",
            resources: [
                .copy("Fixtures/ReplayScenario.json")
            ],
            swiftSettings: strictSwiftSettings
        )
    ]
)
