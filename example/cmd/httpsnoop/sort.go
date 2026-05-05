package main

import (
	"cmp"
	"go/version"
	"slices"
	"strings"
)

func compareGoVersion(a, b string) int {
	// Support old versions of go that used " " between experimental flags.
	// Newer versions of go use "-".
	a = strings.ReplaceAll(a, " ", "-")
	b = strings.ReplaceAll(b, " ", "-")

	if c := version.Compare(a, b); c != 0 {
		return c
	}
	return cmp.Compare(a, b)
}

func sortByGoVersion(results []*ProcessInfo) {
	slices.SortFunc(results, func(a, b *ProcessInfo) int {
		return compareGoVersion(a.GoVersion, b.GoVersion)
	})
}
