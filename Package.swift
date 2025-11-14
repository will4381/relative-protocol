// swift-tools-version: 5.9

//
//  Package.swift
//  RelativeProtocol
//
//  Copyright (c) 2025 Relative Companies, Inc.
//  Personal, non-commercial use only. Created by Will Kusch on 10/21/2025.
//
//  Defines the RelativeProtocol Swift package products, dependencies, and targets.
//

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
    dependencies: [],
    targets: [
        // Vendored binary (prebuilt) relative to repo root
        .binaryTarget(
            name: "EngineBinary",
            path: "RelativeProtocol/Binary/Engine.xcframework"
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
            dependencies: [],
            path: "RelativeProtocol/Sources/RelativeProtocolCore"
        ),
        .target(
            name: "RelativeProtocolTunnel",
            dependencies: [
                "RelativeProtocolCore",
                "EngineBinary"
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
