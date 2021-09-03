// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SwCryptRSAPSS",
    products: [
        .library(name: "SwCryptRSAPSS",
                 type: .static,
                 targets: ["SwCryptRSAPSS"])
    ],
    targets: [
        .target(name: "SwCryptRSAPSS",
                path: "SwCryptRSAPSS",
                exclude: ["Info.plist"]),
        .testTarget(name: "SwCryptRSAPSSTests",
                    dependencies: ["SwCryptRSAPSS"],
                    path: "SwCryptRSAPSSTests",
                    exclude: ["Info.plist"])
    ]
)
