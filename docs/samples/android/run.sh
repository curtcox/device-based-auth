#!/usr/bin/env bash
# Compile and run the Android sample's shared code on a JVM (Java 17+), and type-check the
# Android-only key class against minimal API stubs, so CI catches drift in both.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -Xlint:all -Werror --release 17 -d "$out/stubs" $(find "$here/jvm-stubs" -name '*.java')
javac -Xlint:all,-deprecation -Werror --release 17 -cp "$out/stubs" -d "$out/classes" "$here/DbaClient.java" "$here/AndroidKeystoreKeys.java" "$here/Main.java"
java -cp "$out/classes" org.devicebasedauth.sample.Main
