BINARY      := httpsnoop

.PHONY: generate build test clean

all: generate build test

bpf/.generate.stamp: bpf/uprobe.bpf.c
	go generate ./...
	@touch $@

generate: bpf/.generate.stamp

build:
	go build -o $(BINARY) ./example/cmd/httpsnoop

test: build
	go vet ./...
	go test ./...

clean:
	rm -f $(BINARY) ./example/cmd/httpsnoop/$(BINARY)
	rm -f bpf/vmlinux.h bpf/uprobehttp_* bpf/.generate.stamp
