//go:build linux

package main

import (
	"debug/buildinfo"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// ProcessInfo represents the inspection result for a Go process or binary.
// Core fields are always populated; verbose fields use omitempty.
type ProcessInfo struct {
	PID       int    `json:"pid,omitempty"`
	Exe       string `json:"exe"`
	Path      string `json:"path"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	ExeMTime  int64  `json:"exe_mtime"`

	// Populated unconditionally but only included in output when non-empty.
	PackagePath string `json:"package,omitempty"`

	// Populated for running PIDs; callers may set these after calling Inspect.
	GoEnv   map[string]string `json:"go_env,omitempty"`
	Cmdline string            `json:"cmdline,omitempty"`

	// Verbose-only fields (omitted unless --verbose).
	GoBuild map[string]string `json:"go_build,omitempty"`
}

// readBuildInfo reads Go build information from a binary path or PID string.
// For PID targets, it opens /proc/<pid>/exe on Linux.
// Returns the BuildInfo and the resolved executable path.
func readBuildInfo(pid int) (*buildinfo.BuildInfo, string, error) {
	path, err := procExePath(int(pid))
	if err != nil {
		return nil, "", err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	bi, err := buildinfo.Read(f)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}

	path = resolveExePath(path)
	return bi, path, nil
}

// resolveVersion returns the module version suitable for display, substituting
// fallback when the buildinfo version is missing or a pseudo-"(devel)" marker.
func resolveVersion(version, fallback string) string {
	if version == "" || version == "(devel)" {
		return fallback
	}
	return version
}

// Inspect reads build information for a Go process and returns a populated
// ProcessInfo. When verbose is true, build settings are included.
//
// GoEnv and Cmdline are not populated by Inspect; callers that need them
// should read /proc/<pid>/environ and /proc/<pid>/cmdline directly.
func Inspect(pid int, verbose bool) (*ProcessInfo, error) {
	start := time.Now()
	bi, exe, err := readBuildInfo(pid)
	if err != nil {
		return nil, err
	}

	info := &ProcessInfo{
		PID:       pid,
		Exe:       exe,
		Path:      bi.Path,
		Version:   resolveVersion(bi.Main.Version, "devel"),
		GoVersion: bi.GoVersion,
	}

	if stat, err := os.Stat(exe); err == nil {
		info.ExeMTime = stat.ModTime().Unix()
	}

	if bi.Path != "" {
		info.PackagePath = bi.Path + "@" + resolveVersion(bi.Main.Version, "latest")
	}

	if verbose {
		info.GoBuild = make(map[string]string, len(bi.Settings))
		for _, s := range bi.Settings {
			info.GoBuild[s.Key] = s.Value
		}
	}

	slog.Debug("inspect complete", "pid", pid, "elapsed", time.Since(start))
	return info, nil
}
