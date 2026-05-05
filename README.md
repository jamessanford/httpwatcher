# go-httpsnoop

`go-httpsnoop` is a Go library that traces outbound HTTP requests made by running Go processes. It attaches Linux uprobes to `net/http.(*Client).do` using eBPF.  It captures a subset of the http.Request: method, URL, and header map.

This library and eBPF code was written by Claude Code and Claude Sonnet 4.6.

## Library usage

```go
import "github.com/jamessanford/httpsnoop"

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

snoop, err := httpsnoop.Init(ctx)
if err != nil {
    log.Fatal(err)
}

snoop.Attach(pid)
snoop.Attach(pid2)

for ev := range snoop.Events() {
    fmt.Printf("%s %s\n", ev.Method, ev.URL)
    for k, v := range ev.Headers {
        fmt.Printf("  %s: %s\n", k, v)
    }
}
```

`Events()` returns a channel that is closed when the context is cancelled. Any uprobe links are cleaned up automatically.

## Requirements

- Linux with eBPF support (kernel 5.8+)
- Root or `CAP_BPF` + `CAP_PERFMON` capabilities
- Target processes must be Go 1.17+ (register-based calling convention)

## Example command

`example/cmd/httpsnoop` is a CLI that wraps the library. It can inspect Go binaries and running processes, and attach uprobes to trace their HTTP traffic.

```bash
go build -o httpsnoop ./example/cmd/httpsnoop
```

```bash
# Scan running Go processes and trace their HTTP requests
sudo ./httpsnoop --bpf

# Trace a specific PID
sudo ./httpsnoop --bpf --pid 1234
```

```
Trace HTTP outgoing requests of running Go processes

Usage:
  httpsnoop [flags] [pid...]

Flags:
      --bpf       Attach eBPF http uprobes
  -p, --pid       Inspect PIDs (default true)
  -j, --json      Output JSON
  -s, --sort      Sort output by Go version
      --debug     Log process scans to stderr
      --verbose   Include build settings in JSON
  -h, --help      help for httpsnoop
```

## Build

```bash
make generate  # compile BPF and regenerate Go bindings (requires clang + bpftool)
make build     # build the example command binary
```

For the BPF component, see S[bpf/README.md](bpf/README.md) for toolchain setup and build instructions.

## How it works

`Init` loads an eBPF program compiled from `bpf/uprobe.bpf.c` (embedded in the binary). `Attach` resolves struct field offsets from the target binary's DWARF info, writes them into a BPF map, and installs a uprobe on `net/http.(*Client).do`. The BPF program reads the HTTP request fields from Go's register-based ABI and sends them through a ring buffer.
