package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_test(
    name = "go_default_test",
    srcs = ["alicloud_test.go"],
    library = "go_default_library",
    tags = ["automanaged"],
    deps = [
        "//pkg/api/v1:go_default_library",
        "//pkg/types:go_default_library",
        "//pkg/util/intstr:go_default_library",
        "//vendor:github.com/denverdino/aliyungo/slb",
    ],
)

go_library(
    name = "go_default_library",
    srcs = [
        "alicloud.go",
        "alicloud_instances.go",
        "alicloud_loadbalancer.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//pkg/api:go_default_library",
        "//pkg/api/v1:go_default_library",
        "//pkg/cloudprovider:go_default_library",
        "//pkg/types:go_default_library",
        "//vendor:github.com/denverdino/aliyungo/common",
        "//vendor:github.com/denverdino/aliyungo/ecs",
        "//vendor:github.com/denverdino/aliyungo/metadata",
        "//vendor:github.com/denverdino/aliyungo/slb",
        "//vendor:github.com/golang/glog",
    ],
)
