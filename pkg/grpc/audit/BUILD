load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "audit_proto",
    srcs = ["audit.proto"],
    deps = ["@envoy_api//:v3_protos"],
)

go_proto_library(
    name = "audit_go_proto",
    importpath = "github.com/pomerium/pomerium/pkg/grpc/audit",
    proto = ":audit_proto",
    deps = ["@com_github_envoyproxy_go_control_plane//envoy/service/auth/v3:go_default_library"],
)

go_library(
    name = "audit",
    embed = [":audit_go_proto"],
    importpath = "github.com/pomerium/pomerium/pkg/grpc/audit",
)
