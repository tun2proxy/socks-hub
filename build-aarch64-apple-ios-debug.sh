#! /bin/sh

echo "Setting up the rust environment..."
rustup target add aarch64-apple-ios
cargo install cbindgen

echo "Building target aarch64-apple-ios..."
cargo build --target aarch64-apple-ios

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

echo "Creating XCFramework"
rm -rf ./socks-hub.xcframework
xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-ios/debug/libsocks_hub.a -headers ./target/include/ \
    -output ./socks-hub.xcframework
