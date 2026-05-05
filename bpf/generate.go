package bpf

//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64,arm UprobeHTTP uprobe.bpf.c -- -Wno-missing-declarations
