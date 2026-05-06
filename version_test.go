package httpwatcher

import (
	"testing"
)

func TestCompareGoVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"go1.25.5 X:nodwarf5", "go1.17", 1},
		{"go1.26.2-X:nodwarf5", "go1.24", 1},
		{"go1.17 X:test", "go1.17", 1},
		{"go1.17.0 X:test", "go1.17", 1},
		{"go1.19", "go1.19rc1", 1},
		{"go1.17rc1", "go1.17", -1},
		{"not-a-version", "go1.26.2", -1},
	}

	for _, tt := range tests {
		got := compareGoVersion(tt.a, tt.b)
		if got != tt.want {
			t.Fatalf("compareGoVersion(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
