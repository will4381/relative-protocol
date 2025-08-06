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
            targets: ["RelativeProtocolWrapper"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "RelativeProtocol",
            path: "RelativeProtocol.xcframework"
        ),
        .target(
            name: "RelativeProtocolWrapper",
            dependencies: ["RelativeProtocol"],
            linkerSettings: [
                .linkedFramework("CoreTelephony"),
                .linkedFramework("NetworkExtension")
            ]
        )
    ]
)