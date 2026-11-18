// swift-tools-version:5.9
// The iOS sample as a Swift package: copy Sources/DbaClient into an app (iOS 15+), or depend on it.
// CI builds it on macOS and runs Sources/dba-sample against a local server (run.sh).
import PackageDescription

let package = Package(
    name: "DbaClient",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "DbaClient", targets: ["DbaClient"])],
    targets: [
        .target(name: "DbaClient"),
        .executableTarget(name: "dba-sample", dependencies: ["DbaClient"])
    ]
)
