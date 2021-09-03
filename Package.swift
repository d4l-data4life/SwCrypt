// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "Data4LifeCryptoRSAPSS",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)],
    products: [
        .library(name: "Data4LifeCryptoRSAPSS",
                 type: .static,
                 targets: ["Data4LifeCryptoRSAPSS"])
    ],
    targets: [
        .target(name: "Data4LifeCryptoRSAPSS",
                path: "Data4LifeCryptoRSAPSS"),
        .testTarget(name: "Data4LifeCryptoRSAPSSTests",
                    dependencies: ["Data4LifeCryptoRSAPSS"],
                    path: "Data4LifeCryptoRSAPSSTests")
    ]
)
