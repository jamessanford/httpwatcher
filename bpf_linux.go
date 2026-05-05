//go:build linux

package httpebpf

import (
	"structs"
)

// probeSymbol is the Go symbol we attach the uprobe to.
const probeSymbol = "net/http.(*Client).do"

// offTable is the BPF map value written to go_offsets_map.
// Field order and types must match off_table_t in uprobe.bpf.c exactly.
type offTable struct {
	_             structs.HostLayout
	RequestMethod uint64
	RequestURL    uint64
	URLScheme     uint64
	URLHost       uint64
	URLPath       uint64
	URLRawQuery   uint64
	RequestHeader uint64
	SwissTables   uint64 // 1 if binary uses Go 1.24+ Swiss tables map format
}

// rawHTTPEvent mirrors struct http_event in uprobe.bpf.c.
// Field sizes and order must match exactly.
const (
	evMaxStr    = 64
	evMaxHdr    = 16
	evMaxHdrKey = 64
	evMaxHdrVal = 512
)

type rawHTTPEvent struct {
	_        structs.HostLayout
	PID      uint64
	Method   [evMaxStr]byte
	Scheme   [evMaxStr]byte
	Host     [evMaxStr]byte
	Path     [evMaxStr]byte
	Query    [evMaxStr]byte
	NHeaders uint64
	Keys     [evMaxHdr][evMaxHdrKey]byte
	Vals     [evMaxHdr][evMaxHdrVal]byte
}
