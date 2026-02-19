// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "relative-protocol",
    platforms: [
        .iOS(.v15),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RelativeProtocolCore", targets: ["RelativeProtocolCore"]),
        .library(name: "RelativeProtocolHost", targets: ["RelativeProtocolHost"]),
        .library(name: "RelativeProtocolTunnel", targets: ["RelativeProtocolTunnel"])
    ],
    targets: [
        .target(
            name: "HevSocks5Tunnel",
            path: "RelativeProtocol/ThirdParty/hev-socks5-tunnel",
            exclude: [
                ".clang-format",
                "conf",
                "third-part/hev-task-system/configs.mk",
                "third-part/hev-task-system/apps",
                "third-part/hev-task-system/tests",
                "third-part/hev-task-system/src/kern/io/hev-task-io-reactor-epoll.c",
                "third-part/hev-task-system/src/kern/io/hev-task-io-reactor-iocp.c",
                "third-part/hev-task-system/src/kern/task/hev-task-execute.S",
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
                "third-part/lwip/.git",
                "third-part/lwip/src/netif",
                "third-part/lwip/src/ports/unix",
                "third-part/lwip/src/ports/win32",
                "third-part/yaml/.git",
                "third-part/yaml/.gitlab-ci.yml",
                "third-part/yaml/configs.mk",
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
            name: "RelativeProtocolCore",
            path: "RelativeProtocol/Sources/RelativeProtocolCore"
        ),
        .target(
            name: "RelativeProtocolHost",
            dependencies: ["RelativeProtocolCore"],
            path: "RelativeProtocol/Sources/RelativeProtocolHost"
        ),
        .target(
            name: "RelativeProtocolTunnel",
            dependencies: ["RelativeProtocolCore", "HevSocks5Tunnel"],
            path: "RelativeProtocol/Sources/RelativeProtocolTunnel"
        ),
        .testTarget(
            name: "RelativeProtocolCoreTests",
            dependencies: ["RelativeProtocolCore", "RelativeProtocolHost"],
            path: "RelativeProtocol/Tests/RelativeProtocolCoreTests"
        ),
        .testTarget(
            name: "RelativeProtocolTunnelTests",
            dependencies: ["RelativeProtocolTunnel"],
            path: "RelativeProtocol/Tests/RelativeProtocolTunnelTests"
        )
    ]
)
