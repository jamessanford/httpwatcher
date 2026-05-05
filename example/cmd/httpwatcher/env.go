package main

import (
	"strings"
)

// goEnvKeys lists Go runtime environment variables worth reporting, in the
// order they should appear in tabular output. These control scheduler, GC,
// and debug behavior at process startup.
var goEnvKeys = []string{
	"GOGC",
	"GODEBUG",
	"GOMAXPROCS",
	"GOMEMLIMIT",
	"GORACE",
	"GOTRACEBACK",
}

var goEnvKeySet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(goEnvKeys))
	for _, k := range goEnvKeys {
		m[k] = struct{}{}
	}
	return m
}()

func isGoEnvKey(k string) bool {
	_, ok := goEnvKeySet[k]
	return ok
}

func filterGoEnv(entries []string) map[string]string {
	var env map[string]string
	for _, entry := range entries {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || !isGoEnvKey(k) {
			continue
		}
		if env == nil {
			env = make(map[string]string)
		}
		env[k] = v
	}
	return env
}
