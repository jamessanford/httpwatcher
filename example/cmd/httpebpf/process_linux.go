//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// procExePath returns the /proc/<pid>/exe path for the given PID.
func procExePath(pid int) (string, error) {
	return fmt.Sprintf("/proc/%d/exe", pid), nil
}

// resolveExePath resolves a /proc/<pid>/exe symlink to the real binary path.
func resolveExePath(procPath string) string {
	link, err := os.Readlink(procPath)
	if err != nil {
		return procPath
	}
	return link
}

func readGoEnv(pid int) map[string]string {
	start := time.Now()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		slog.Debug("readGoEnv", "pid", pid, "elapsed", time.Since(start), "error", err)
		return nil
	}
	slog.Debug("readGoEnv", "pid", pid, "elapsed", time.Since(start), "bytes", len(data))
	return filterGoEnv(strings.Split(string(data), "\x00"))
}

func readCmdline(pid int) string {
	start := time.Now()
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		slog.Debug("readCmdline", "pid", pid, "elapsed", time.Since(start), "error", err)
		return ""
	}
	slog.Debug("readCmdline", "pid", pid, "elapsed", time.Since(start), "bytes", len(cmdline))
	return strings.TrimRight(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")
}

func listGoPIDs() ([]int, error) {
	start := time.Now()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	slog.Debug("listGoPIDs", "elapsed", time.Since(start), "count", len(pids))
	return pids, nil
}
