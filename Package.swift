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
        .binaryTarget(
            name: "RelativeProtocol",
            path: "RelativeProtocol.xcframework"
        ),
    ]
)