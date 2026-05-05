httpebpf is a Go library to trace outbound HTTP requests of running Go processes. It attaches Linux eBPF uprobes to `net/http.(*Client).do`.  A subset of the original `http.Request` is returned.

The library and eBPF code are written by Claude Code and Claude Sonnet 4.6.

## Library usage

```go
import "github.com/jamessanford/httpebpf"

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

snoop, err := httpebpf.Init(ctx)
if err != nil {
    log.Fatal(err)
}
defer snoop.Close()

snoop.Attach(pid)
snoop.Attach(pid2)

for ev := range snoop.Events() {
    fmt.Printf("%d %s %s\n", ev.PID, ev.Method, ev.URL)
    for k, v := range ev.Headers {
        fmt.Printf("  %s: %s\n", k, v)
    }
}
```

`Events()` returns a channel that is closed when the context is cancelled or Close is called.

## Requirements

- Linux with eBPF support (kernel 5.8+)
- Root or `CAP_BPF` + `CAP_PERFMON` capabilities
- Target processes must be Go 1.17+ (register-based calling convention)

## Example command

`example/cmd/httpebpf` is a sample CLI that wraps the library.

```bash
go build -o httpebpf ./example/cmd/httpebpf

# You may also install it:
# go install github.com/jamessanford/httpebpf/example/cmd/httpebpf@latest
```

```bash
# Find running Go processes
sudo ./httpebpf

# Scan running Go processes and trace their HTTP requests
sudo ./httpebpf --bpf

# Trace a specific PID
sudo ./httpebpf --bpf --pid 1234
```

```
Trace HTTP outgoing requests of running Go processes

Usage:
  httpebpf [flags] [pid...]

Flags:
      --bpf       Attach eBPF http uprobes
  -p, --pid       Inspect PIDs (default true)
  -j, --json      Output JSON
  -s, --sort      Sort output by Go version
      --debug     Log process scans to stderr
      --verbose   Include build settings in JSON
  -h, --help      help for httpebpf
```
