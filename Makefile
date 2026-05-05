BINARY      := httpebpf

.PHONY: generate build test clean

all: generate build test

bpf/.generate.stamp: bpf/uprobe.bpf.c
	go generate ./...
	@touch $@

generate: bpf/.generate.stamp

build:
	go build -o $(BINARY) ./example/cmd/httpebpf

test: build
	go vet ./...
	go test ./...

clean:
	rm -f $(BINARY) ./example/cmd/httpebpf/$(BINARY)
	rm -f bpf/vmlinux.h bpf/uprobehttp_* bpf/.generate.stamp
