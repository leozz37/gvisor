go_library(
    name = "context",
    testonly = 1,
    srcs = [
        "context.go",
        "flow.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
        "@org_golang_x_time//rate:go_default_library",
    ],
)
