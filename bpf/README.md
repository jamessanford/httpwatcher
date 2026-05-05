# BPF Notes

The BPF source is `bpf/uprobe.bpf.c`. For the library, the compiled objects are
generated via `go generate` which runs bpf2go.  Read on to build or verify manually.

This eBPF code was written by Claude Code and Claude Sonnet 4.6.

## Build

Install the BPF toolchain:

```
clang  llvm  bpftool  libbpf (headers + development package)
```

Then run make — it generates `bpf/vmlinux.h` from the running kernel's BTF,
compiles the BPF object, and regenerates the Go bindings via bpf2go:

```bash
make generate  # generates bpf/vmlinux.h, compiles BPF, runs go generate
make build     # builds the example command (no BPF toolchain needed)
```

`bpf/vmlinux.h` is machine-generated and gitignored; rebuild it whenever you
move to a different kernel. The generated `uprobehttp_*.go` files are committed
so that `make build` or `go install` work without clang.

## Verify the object without running the binary

**Inspect sections and maps:**

```bash
clang -O2 -g -target bpf -Ibpf/ -c bpf/uprobe.bpf.c -o bpf/uprobe.bpf.o
llvm-readelf -S bpf/uprobe.bpf.o        # ELF sections (.maps, uprobe/, .BTF, …)
bpftool btf dump file bpf/uprobe.bpf.o  # BTF types — confirms CO-RE info is present
```

**Disassemble the BPF bytecode:**

```bash
llvm-objdump -d bpf/uprobe.bpf.o
```

**Load and verify (runs the BPF verifier; requires root):**

```bash
sudo bpftool prog load bpf/uprobe.bpf.o /sys/fs/bpf/httpsnoop_test type uprobe
sudo bpftool prog show pinned /sys/fs/bpf/httpsnoop_test
sudo rm /sys/fs/bpf/httpsnoop_test
```

A successful load means the verifier accepted the program on this kernel.

## CO-RE

The program uses `BPF_CORE_READ(ctx, bx)` to read the Go BX register from
`struct pt_regs`. At load time, libbpf relocates the field offset to match
the running kernel's actual `pt_regs` layout using the embedded BTF.

Go struct field offsets (method, URL, headers) are handled separately by
DWARF-based offset detection in `offsets_linux.go`. The resolved offsets are
written into a BPF map before the uprobe is attached — no CO-RE relocation is
needed for them.

## Struct offset resolution

When httpsnoop's `Attach(pid)` is called, the library reads the target binary's
DWARF debug info to find the byte offsets of `net/http.Request.{Method,URL,Header}`
and `net/url.URL.{Scheme,Host,Path,RawQuery}`. These offsets are written into a
per-PID BPF hash map before the uprobe fires, so the BPF program always has
correct offsets even when attaching to multiple binaries built with different
Go versions. If DWARF info is stripped (e.g., `-ldflags="-s -w"`), known-good
amd64 defaults are used instead.
