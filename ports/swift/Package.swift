// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "unicode-security-swift",
    products: [
        .library(name: "UnicodeSecurity", targets: ["UnicodeSecurity"]),
    ],
    targets: [
        .target(
            name: "UnicodeSecurity",
            resources: [.process("Resources")]
        ),
        .executableTarget(
            name: "UnicodeSecurityContractTests",
            dependencies: ["UnicodeSecurity"],
            path: "ContractTests",
            resources: [.process("Resources")]
        ),
    ]
)
