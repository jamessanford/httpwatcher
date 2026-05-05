// Package httpsnoop traces outbound HTTP requests made by Go processes.
// It attaches Linux uprobes to net/http.(*Client).do using eBPF.
// The events returned are a subset of the original http.Request,
// with truncated strings and headers.
//
// Basic usage:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	snoop, err := httpsnoop.Init(ctx)
//	if err != nil { ... }
//	if err := snoop.Attach(pid); err != nil { ... }
//	for ev := range snoop.Events() {
//	    fmt.Printf("%d %s %s\n", ev.PID, ev.Method, ev.URL)
//	    for k, v := range ev.Headers {
//	           fmt.Printf("  %s: %s\n", k, v)
//	       }
//	}
package httpsnoop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/version"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/jamessanford/httpsnoop/bpf"
)

// HTTPEvent is an outbound HTTP request captured from an instrumented process.
type HTTPEvent struct {
	PID     int               // PID of the process that issued the request
	Method  string            // HTTP method (e.g. "GET", "POST")
	URL     string            // Reconstructed URL; each component truncated to 64 bytes
	Headers map[string]string // Request headers; at most 16 entries, keys ≤64 bytes, values ≤512 bytes
}

// Snooper manages uprobe-based HTTP request interception for multiple processes.
type Snooper struct {
	objs   bpf.UprobeHTTPObjects
	rd     *ringbuf.Reader
	events chan HTTPEvent
	links  []link.Link
	mu     sync.Mutex
}

// Init loads the uprobe BPF program and starts the event loop.
// The returned Snooper delivers events until ctx is cancelled, at which point
// the Events channel is closed and all uprobe links are released.
func Init(ctx context.Context) (*Snooper, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs bpf.UprobeHTTPObjects
	if err := bpf.LoadUprobeHTTPObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load uprobe BPF: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	s := &Snooper{
		objs:   objs,
		rd:     rd,
		events: make(chan HTTPEvent, 64),
	}

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	go s.readLoop()
	return s, nil
}

// Attach installs an HTTP uprobe on the process with the given PID.
// It reads the binary's build info to verify Go version compatibility and
// resolve struct field offsets.
func (s *Snooper) Attach(pid int) error {
	exePath, err := procExePath(pid)
	if err != nil {
		return fmt.Errorf("pid %d: resolve exe path: %w", pid, err)
	}

	bi, _, err := readBuildInfo(pid)
	if err != nil {
		return fmt.Errorf("pid %d: read build info: %w", pid, err)
	}

	// Go <1.17 uses stack-based ABI; the request pointer is not in BX.
	if bi.GoVersion != "" && version.Compare(bi.GoVersion, "go1.17") < 0 {
		return fmt.Errorf("pid %d: Go version %s predates register ABI (need >=go1.17)", pid, bi.GoVersion)
	}

	offs := resolveOffsets(exePath)
	swissTables := uint64(1)
	if bi.GoVersion != "" && version.Compare(bi.GoVersion, "go1.24") < 0 {
		swissTables = 0
	}

	// Populate the offsets map before attaching the uprobe so the BPF
	// program never sees a missing entry.
	if err := s.objs.GoOffsetsMap.Put(uint32(pid), offTable{
		RequestMethod: offs.RequestMethod,
		RequestURL:    offs.RequestURL,
		URLScheme:     offs.URLScheme,
		URLHost:       offs.URLHost,
		URLPath:       offs.URLPath,
		URLRawQuery:   offs.URLRawQuery,
		RequestHeader: offs.RequestHeader,
		SwissTables:   swissTables,
	}); err != nil {
		return fmt.Errorf("pid %d: write offsets map: %w", pid, err)
	}

	exec, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("pid %d: open executable: %w", pid, err)
	}

	uprobe, err := exec.Uprobe(probeSymbol, s.objs.HandleUprobe, &link.UprobeOptions{PID: pid})
	if err != nil {
		// Symbol may not be present in binaries that don't use net/http.
		return fmt.Errorf("pid %d: attach uprobe: %w", pid, err)
	}

	s.mu.Lock()
	s.links = append(s.links, uprobe)
	s.mu.Unlock()
	return nil
}

// Events returns the channel on which captured HTTP events are delivered.
// The channel is closed when the context passed to Init is cancelled.
func (s *Snooper) Events() <-chan HTTPEvent {
	return s.events
}

// TODO: Should we have a "Close" that also cancels it, and then actually waits for readLoop cleanup to finish?
func (s *Snooper) readLoop() {
	defer close(s.events)
	defer s.objs.Close()
	defer s.rd.Close()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, l := range s.links {
			l.Close()
		}
	}()

	for {
		rec, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Info("ringbuf read", "err", err)
			continue
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			slog.Info("decode event", "err", err)
			continue
		}
		s.events <- ev
	}
}

func decodeEvent(raw []byte) (HTTPEvent, error) {
	var ev rawHTTPEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return HTTPEvent{}, err
	}

	scheme := nullStr(ev.Scheme[:])
	host := nullStr(ev.Host[:])
	path := nullStr(ev.Path[:])
	query := nullStr(ev.Query[:])

	url := scheme + "://" + host + path
	if query != "" {
		url += "?" + query
	}

	n := int(ev.NHeaders)
	if n > evMaxHdr {
		n = evMaxHdr
	}
	headers := make(map[string]string, n)
	for i := 0; i < n; i++ {
		headers[nullStr(ev.Keys[i][:])] = nullStr(ev.Vals[i][:])
	}

	return HTTPEvent{
		PID:     int(ev.PID),
		Method:  nullStr(ev.Method[:]),
		URL:     url,
		Headers: headers,
	}, nil
}

func nullStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
