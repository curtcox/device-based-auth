#!/usr/bin/env bash
# Build the iOS sample, type-check its library for iOS when Xcode has the iOS SDK, and run the
# command-line client against DBA_ORIGIN with a software key (macOS; how CI tests this sample).
#
#     DBA_ORIGIN=http://localhost:8787 bash docs/samples/ios/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if sdk="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)"; then
  xcrun swiftc -typecheck -warnings-as-errors -target arm64-apple-ios15.0 -sdk "$sdk" -module-name DbaClient "$here"/Sources/DbaClient/*.swift
fi
swift build --package-path "$here" -Xswiftc -warnings-as-errors >&2
"$(swift build --package-path "$here" --show-bin-path)/dba-sample"
