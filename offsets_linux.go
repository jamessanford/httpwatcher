//go:build linux

package httpsnoop

import (
	"debug/dwarf"
	"debug/elf"
	"log/slog"
)

// fieldOffsets holds byte offsets for the Go struct fields read in the uprobe.
type fieldOffsets struct {
	RequestMethod uint64 // net/http.Request.Method  (string header start)
	RequestURL    uint64 // net/http.Request.URL     (pointer to *url.URL)
	URLScheme     uint64 // net/url.URL.Scheme       (string header start)
	URLHost       uint64 // net/url.URL.Host         (string header start)
	URLPath       uint64 // net/url.URL.Path         (string header start)
	URLRawQuery   uint64 // net/url.URL.RawQuery     (string header start)
	RequestHeader uint64 // net/http.Request.Header  (map[string][]string pointer)
}

// defaultOffsets are the known-good amd64 Go 1.17+ values, used when the
// target binary has no DWARF debug info (e.g. built with -ldflags="-s -w").
var defaultOffsets = fieldOffsets{
	RequestMethod: 0,
	RequestURL:    16,
	URLScheme:     0,
	URLHost:       40,
	URLPath:       56,
	URLRawQuery:   88,
	RequestHeader: 56, // after Method(16)+URL(8)+Proto(16)+ProtoMajor(8)+ProtoMinor(8)
}

// resolveOffsets returns struct field byte offsets by reading DWARF debug info
// from exePath. Falls back to defaultOffsets if DWARF is unavailable.
func resolveOffsets(exePath string) fieldOffsets {
	offs, err := dwarfOffsets(exePath)
	if err != nil {
		slog.Debug("DWARF offset extraction failed, using defaults", "path", exePath, "err", err)
		return defaultOffsets
	}
	slog.Debug("resolved offsets from DWARF",
		"path", exePath,
		"request.Method", offs.RequestMethod,
		"request.URL", offs.RequestURL,
		"url.Scheme", offs.URLScheme,
		"url.Host", offs.URLHost,
		"url.Path", offs.URLPath,
		"url.RawQuery", offs.URLRawQuery,
	)
	return offs
}

// dwarfOffsets walks the DWARF debug info in the ELF binary at exePath,
// extracting byte offsets for fields in net/http.Request and net/url.URL.
// It starts from defaultOffsets, so any fields not found in DWARF retain
// the known-good fallback value.
func dwarfOffsets(exePath string) (fieldOffsets, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		return defaultOffsets, err
	}
	defer f.Close()

	d, err := f.DWARF()
	if err != nil {
		return defaultOffsets, err
	}

	offs := defaultOffsets

	// targets maps struct name → (field name → pointer into offs).
	targets := map[string]map[string]*uint64{
		"net/http.Request": {
			"Method": &offs.RequestMethod,
			"URL":    &offs.RequestURL,
			"Header": &offs.RequestHeader,
		},
		"net/url.URL": {
			"Scheme":   &offs.URLScheme,
			"Host":     &offs.URLHost,
			"Path":     &offs.URLPath,
			"RawQuery": &offs.URLRawQuery,
		},
	}

	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType || !entry.Children {
			continue
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		fields, ok := targets[name]
		if !ok {
			reader.SkipChildren()
			continue
		}
		for {
			child, err := reader.Next()
			if err != nil || child == nil || child.Tag == 0 {
				break
			}
			if child.Tag != dwarf.TagMember {
				continue
			}
			fieldName, _ := child.Val(dwarf.AttrName).(string)
			ptr, ok := fields[fieldName]
			if !ok {
				continue
			}
			if loc, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
				*ptr = uint64(loc)
			}
		}
	}
	return offs, nil
}
