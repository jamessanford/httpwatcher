### httpebpf example binary

This example `httpebpf` is a variant of [gover](https://github.com/jamessanford/gover)
hooked up to the [httpebpf](https://github.com/jamessanford/httpebpf) library.

By default it lists running Go programs.  Add `--bpf` to attach and show outgoing HTTP requests.

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
