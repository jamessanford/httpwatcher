package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jamessanford/httpwatcher"
	"github.com/spf13/cobra"
)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func printJSON(results []*ProcessInfo) error {
	enc := json.NewEncoder(os.Stdout)
	if len(results) == 1 && isTerminal(os.Stdout) {
		enc.SetIndent("", "  ")
	}
	for _, res := range results {
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return nil
}

func formatGoEnv(goEnv map[string]string) string {
	pairs := make([]string, 0, len(goEnv))
	for _, key := range goEnvKeys {
		if val, ok := goEnv[key]; ok {
			pairs = append(pairs, key+"="+val)
		}
	}
	return strings.Join(pairs, " ")
}

func printTable(results []*ProcessInfo) {
	if len(results) == 0 {
		return
	}

	fmt.Printf("To attach, use \"--bpf -p PID\" on a Go process:\n\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tGo Version\tExe\tGo Package\tEnv")
	for _, info := range results {
		binaryName := filepath.Base(info.Exe)
		pid := ""
		if info.PID != 0 {
			pid = fmt.Sprintf("%d", info.PID)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", pid, info.GoVersion, binaryName, info.PackagePath, formatGoEnv(info.GoEnv))
	}
	_ = w.Flush()
}

func pidsAsStrs(pids []int) []string {
	result := make([]string, len(pids))
	for i, v := range pids {
		result[i] = strconv.Itoa(v)
	}
	return result
}

type configFlags struct {
	pid     bool
	json    bool
	sort    bool
	bpf     bool
	debug   bool
	verbose bool
}

func run(flags configFlags, args []string) error {
	level := slog.LevelInfo
	if flags.debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	start := time.Now()
	defer func() {
		slog.Debug("run complete", "elapsed", time.Since(start))
	}()

	scanMode := len(args) == 0
	if scanMode {
		pids, err := listGoPIDs()
		if err != nil {
			return err
		}
		args = pidsAsStrs(pids)
		slog.Debug("scan pid enumeration", "elapsed", time.Since(start), "count", len(pids))
	}

	result := make([]*ProcessInfo, 0, len(args))
	var resultErr error
	for _, arg := range args {
		pid64, err := strconv.ParseInt(arg, 10, 64)
		if err != nil {
			return fmt.Errorf("expected pid, not %v", arg)
		}
		pid := int(pid64)
		res, err := Inspect(pid, flags.verbose)
		if err != nil {
			// Scan mode silently skips inaccessible or non-Go processes.
			// Explicit targets surface the first error at exit.
			if !scanMode && resultErr == nil {
				resultErr = err
			}
			continue
		}
		res.GoEnv = readGoEnv(pid)
		res.Cmdline = readCmdline(pid)
		result = append(result, res)
	}

	if flags.sort {
		sortByGoVersion(result)
	}

	if flags.bpf {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		snoop, err := httpwatcher.Init(ctx)
		if err != nil {
			return err
		}
		defer snoop.Close()

		attached := 0
		for _, info := range result {
			if info == nil || info.PID == 0 {
				continue
			}
			if err := snoop.Attach(info.PID); err != nil {
				slog.Info("skip", "pid", info.PID, "exe", info.Exe, "err", err)
				continue
			}
			slog.Info("attached", "pid", info.PID, "exe", info.Exe)
			attached++
		}

		if attached == 0 {
			return fmt.Errorf("no processes had symbol %q; nothing to probe", "net/http.(*Client).do")
		}

		slog.Info("uprobe http active, waiting for events (Ctrl-C to exit)", "count", attached)

		for ev := range snoop.Events() {
			if flags.json {
				// HACK
				if err := json.NewEncoder(os.Stdout).Encode(ev); err != nil {
					return err
				}
				continue
			}
			fmt.Printf("%d %s %s\n", ev.PID, ev.Method, ev.URL)
			for k, v := range ev.Headers {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		slog.Info("detaching uprobe http probes")
		return resultErr
	}

	if flags.json {
		if outErr := printJSON(result); outErr != nil {
			return outErr
		}
		return resultErr
	}

	printTable(result)
	return resultErr
}

func main() {
	flags := configFlags{}

	root := &cobra.Command{
		Use:   "httpwatcher [flags] [pid...]",
		Short: "Trace HTTP outgoing requests of running Go processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return run(flags, args)
		},
	}
	root.Flags().SortFlags = false

	root.Flags().BoolVar(&flags.bpf, "bpf", false, "Attach eBPF http uprobes")
	root.Flags().BoolVarP(&flags.pid, "pid", "p", true, "Inspect PIDs")
	root.Flags().BoolVarP(&flags.json, "json", "j", false, "Output JSON")
	root.Flags().BoolVarP(&flags.sort, "sort", "s", false, "Sort output by Go version")
	root.Flags().BoolVar(&flags.debug, "debug", false, "Log process scans to stderr")
	root.Flags().BoolVar(&flags.verbose, "verbose", false, "Include build settings in JSON")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
