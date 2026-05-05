//go:build linux

package httpwatcher

import (
	"debug/buildinfo"
	"fmt"
	"os"
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

// readBuildInfo reads Go build information from a binary path or PID string.
// For PID targets, it opens /proc/<pid>/exe on Linux.
// Returns the BuildInfo and the resolved executable path.
func readBuildInfo(pid int) (*buildinfo.BuildInfo, string, error) {
	path, err := procExePath(pid)
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
