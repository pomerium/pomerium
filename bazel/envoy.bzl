load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

ENVOY_VERSION = "1.25.0"
ENVOY_DARWIN_AMD64_SHA = "41b738e1f8629b13fc7c416764f5ca4ce087ad9024aa6993303fb484b854a1fe"
ENVOY_DARWIN_ARM64_SHA = "b7678333ab693b17a998e2f67dd024ecf7be293fbf7d716784ddca3bee5d006f"
ENVOY_LINUX_AMD64_SHA = "1dfbee4679ef04d3214e445f420d8b96784fa8370fc33b98875d90d2153921f7"
ENVOY_LINUX_ARM64_SHA = "81436c7a48f4f9fc610e2515ac6295b5cdded5196903037b825ddf58d9c2c1c8"

def envoy_binaries():
    http_file(
        name = "envoy_darwin_amd64",
        downloaded_file_path = "envoy-darwin-amd64",
        sha256 = ENVOY_DARWIN_AMD64_SHA,
        url = "https://github.com/pomerium/envoy-binaries/releases/download/v{}/envoy-darwin-amd64".format(ENVOY_VERSION),
    )

    http_file(
        name = "envoy_darwin_arm64",
        downloaded_file_path = "envoy-darwin-arm64",
        sha256 = ENVOY_DARWIN_ARM64_SHA,
        url = "https://github.com/pomerium/envoy-binaries/releases/download/v{}/envoy-darwin-arm64".format(ENVOY_VERSION),
    )

    http_file(
        name = "envoy_linux_amd64",
        downloaded_file_path = "envoy-linux-amd64",
        sha256 = ENVOY_LINUX_AMD64_SHA,
        url = "https://github.com/pomerium/envoy-binaries/releases/download/v{}/envoy-linux-amd64".format(ENVOY_VERSION),
    )

    http_file(
        name = "envoy_linux_arm64",
        downloaded_file_path = "envoy-linux-arm64",
        sha256 = ENVOY_LINUX_ARM64_SHA,
        url = "https://github.com/pomerium/envoy-binaries/releases/download/v{}/envoy-linux-arm64".format(ENVOY_VERSION),
    )