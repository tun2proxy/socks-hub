#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
cargo install cbindgen

echo "Building..."

echo "Building target x86_64-apple-darwin..."
cargo build --release --target x86_64-apple-darwin

echo "Building target aarch64-apple-darwin..."
cargo build --release --target aarch64-apple-darwin

echo "Building target aarch64-apple-ios..."
cargo build --release --target aarch64-apple-ios

echo "Building target x86_64-apple-ios..."
cargo build --release --target x86_64-apple-ios

echo "Building target aarch64-apple-ios-sim..."
cargo build --release --target aarch64-apple-ios-sim

echo "Generating includes..."
mkdir -p target/include/
rm -rf target/include/*
cbindgen --config cbindgen.toml -l C -o target/include/socks-hub.h
cat > target/include/socks-hub.modulemap <<EOF
framework module socks-hub {
    umbrella header "socks-hub.h"

    export *
    module * { export * }
}
EOF

echo "lipo..."

echo "Simulator"
lipo -create \
    target/aarch64-apple-ios-sim/release/libsocks_hub.a \
    target/x86_64-apple-ios/release/libsocks_hub.a \
    -output ./target/libsocks_hub-ios-sim.a

echo "MacOS"
lipo -create \
    target/aarch64-apple-darwin/release/libsocks_hub.a \
    target/x86_64-apple-darwin/release/libsocks_hub.a \
    -output ./target/libsocks_hub-macos.a

echo "Creating XCFramework"
rm -rf ./socks-hub.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/release/libsocks_hub.a -headers ./target/include/ \
    -library ./target/libsocks_hub-ios-sim.a -headers ./target/include/ \
    -library ./target/libsocks_hub-macos.a -headers ./target/include/ \
    -output ./socks-hub.xcframework
