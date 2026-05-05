### httpsnoop example binary

This example `httpsnoop` is a variant of [gover](https://github.com/jamessanford/gover)
hooked up to the [httpsnoop](https://github.com/jamessanford/httpsnoop) library.

By default it lists running Go programs.  Add `--bpf` to attach and show outgoing HTTP requests.

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
