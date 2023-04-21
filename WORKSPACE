load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_skylib",
    sha256 = "b8a1527901774180afc798aeb28c4634bdccf19c4d98e7bdd1ce79d1fe9aaad7",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "ecba0f04f96b4960a5b250c8e8eeec42281035970aa8852dda73098274d14a1d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
    ],
)

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6b65cb7917b4d1709f9410ffe00ecf3e160edf674b78c54a894471320862184f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.39.0/rules_go-v0.39.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.39.0/rules_go-v0.39.0.zip",
    ],
)

http_archive(
    name = "rules_proto_grpc",
    sha256 = "fb7fc7a3c19a92b2f15ed7c4ffb2983e956625c1436f57a3430b897ba9864059",
    strip_prefix = "rules_proto_grpc-4.3.0",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/4.3.0.tar.gz"],
)

http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-21.11",
    urls = [
        "https://github.com/protocolbuffers/protobuf/archive/v21.11.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(version = "1.19")

load("@bazel_gazelle//:deps.bzl", "go_repository")
go_repository(
    name = "com_github_census_instrumentation_opencensus_proto",
    importpath = "github.com/census-instrumentation/opencensus-proto",
    sum = "h1:glEXhBS5PSLLv4IXzLA5yPRVX4bilULVyxxbrfOtDAk=",
    version = "v0.2.1",
    build_extra_args = ["-exclude=src"],  # keep        
)



load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

load("@rules_proto_grpc//:repositories.bzl", "rules_proto_grpc_repos", "rules_proto_grpc_toolchains")

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
git_repository(
    name = "protoc-gen-validate",
    commit = "758c5fc3a13b71bdb7e851b0c1ee8f6232e0ce7d", #tag v0.6.1
    remote = "https://github.com/bufbuild/protoc-gen-validate",
)

git_repository(
    name = "envoy_api",
    commit = "d5b023a95e020c92044a098b75fc06a67e8b6057",
    remote = "https://github.com/envoyproxy/data-plane-api",
)

ENVOY_SHA = "4c12d8eda176081a493968709d510065d715347b"

http_archive(
    name = "envoy",
    strip_prefix = "envoy-" + ENVOY_SHA,
    url = "https://github.com/envoyproxy/envoy/archive/" + ENVOY_SHA + ".zip",
)

load("@envoy_api//bazel:repositories.bzl", "api_dependencies")

api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()


load("//:deps.bzl", "go_dependencies")

# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

load(
    "@com_github_google_go_jsonnet//bazel:repositories.bzl",
    "jsonnet_go_repositories",
)
jsonnet_go_repositories()

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

http_file(
  name = "envoy_darwin_amd64",
  sha256 = "41b738e1f8629b13fc7c416764f5ca4ce087ad9024aa6993303fb484b854a1fe",
  downloaded_file_path = "envoy-darwin-amd64",
  urls = ["https://github.com/pomerium/envoy-binaries/releases/download/v1.25.0/envoy-darwin-amd64"],
)

load("//bazel:envoy.bzl", "envoy_binaries")
envoy_binaries()