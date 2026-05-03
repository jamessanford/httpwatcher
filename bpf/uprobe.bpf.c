// SPDX-License-Identifier: GPL-2.0

// Uprobe on net/http.(*Client).do
//
// Go 1.17+ register ABI (amd64):
//   integer args: AX, BX, CX, DI, SI, R8, R9, R10, R11
//   (*Client).do(receiver *Client, req *Request, ...)
//     AX = receiver *Client  (ignored here)
//     BX = req *Request

#define __TARGET_ARCH_x86

#include <linux/bpf.h>

// Define x86_64 pt_regs before libbpf headers forward-declare it as an
// incomplete type.  Without vmlinux.h (CO-RE), we must supply the layout
// ourselves so that ctx->rbx compiles.
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;   /* Go register ABI: BX = first integer arg after AX */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;   /* Go register ABI: AX = receiver (for methods) */
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_STR      64
#define MAX_HEADERS  16   /* must be power of 2 */
#define MAX_HDR_KEY  64   /* must be power of 2 */
#define MAX_HDR_VAL  128  /* must be power of 2 */

// Go 1.24+ Swiss tables: internal/runtime/maps layout constants (amd64).
//
// Map struct (internal/runtime/maps.Map):
//   used    uint64          @ +0
//   seed    uintptr         @ +8
//   dirPtr  unsafe.Pointer  @ +16  → *group (small) or *[]*table (large)
//   dirLen  int             @ +24  → 0 for small maps, >0 for large
#define MAP_DIRPTR_OFF  16
#define MAP_DIRLEN_OFF  24

// Group layout for map[string][]string (no padding; all 8-byte aligned):
//   ctrl bytes [8]uint8              @ group+0
//   slot i (0-7) at group+8+i*40:
//     key   string:    ptr @ +0,  len @ +8
//     value []string:  ptr @ +16, len @ +24, cap @ +32
#define SLOT_SIZE       40   /* sizeof(string)+sizeof([]string) = 16+24 */
#define GROUP_SIZE     328   /* 8 ctrl + 8*40 slots */
#define ELEM_OFF        16   /* offset of []string within a slot */

// table struct (internal/runtime/maps.table):
//   used       uint16  @ +0
//   capacity   uint16  @ +2
//   growthLeft uint16  @ +4
//   localDepth uint8   @ +6
//   (1 byte pad for int alignment)
//   index      int     @ +8
//   groups.data        @ +16  (unsafe.Pointer in groupsReference)
//   groups.lengthMask  @ +24  (uint64)
#define TABLE_INDEX_OFF       8
#define TABLE_GROUPS_DATA_OFF 16
#define TABLE_GROUPS_MASK_OFF 24

// A ctrl byte with bit 7 clear is a full (occupied) slot.
// Both ctrlEmpty (0x80) and ctrlDeleted (0xFE) have bit 7 set.
#define CTRL_FULL(c) (!((c) & 0x80))

// Byte offsets for Go struct fields, populated by the loader before attaching.
// Field order must match offTable in bpf_linux.go exactly.
typedef struct {
	__u64 request_method;
	__u64 request_url;
	__u64 url_scheme;
	__u64 url_host;
	__u64 url_path;
	__u64 url_rawquery;
	__u64 request_header;
} off_table_t;

struct http_event {
	char  method[MAX_STR];
	char  scheme[MAX_STR];
	char  host[MAX_STR];
	char  path[MAX_STR];
	char  query[MAX_STR];
	__u64 nheaders;
	char  keys[MAX_HEADERS][MAX_HDR_KEY];
	char  vals[MAX_HEADERS][MAX_HDR_VAL];
};

// Per-CPU scratch for request-line strings.  The BPF stack is only 512 bytes,
// so the five 64-byte buffers live here instead.
struct str_scratch {
	char method[MAX_STR];
	char scheme[MAX_STR];
	char host[MAX_STR];
	char path[MAX_STR];
	char query[MAX_STR];
};

// Context passed to slot_cb through bpf_loop.
// nh is NOT stored here; slot_cb reads and writes ev->nheaders in the
// event_scratch_map instead.  Keeping nh in the context would cause the
// verifier to re-verify slot_cb for every distinct accumulated value of nh
// (0, 1, 2, ..., MAX_HEADERS-1), exploding the state count.  Map value
// loads are treated as opaque bounded scalars by the verifier, so a single
// pass through slot_cb covers all possible nheaders values.
struct slot_ctx {
	__u64 group_base;
	__u32 map_key;  // always 0; stored here to avoid a local stack var
	__u32 _pad;
};

// group_cb needs only the groups array base; nh lives in event_scratch_map.
struct group_ctx {
	__u64 groups_data;
};

// dir_cb needs only the directory pointer; nh lives in event_scratch_map.
struct dir_ctx {
	__u64 dir_ptr;
};

// Context for parse_header_cb: header_map pointer.
// parse_header_cb is invoked via bpf_loop(1, ...) so the verifier processes
// all Swiss tables traversal with a clean register state, independent of
// handle_uprobe's accumulated branch state from string-field reading.
struct parse_hdr_ctx {
	__u64 header_map;
};

// Keyed by PID (TGID); populated by Go before each uprobe is attached.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, off_table_t);
} go_offsets_map SEC(".maps");

// Per-CPU scratch for request-line strings.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct str_scratch);
} str_scratch_map SEC(".maps");

// Per-CPU scratch for the full event struct.  Used during header parsing so
// that the ring buffer pointer never crosses a bpf_loop context boundary,
// which would confuse the BPF verifier's pointer-type tracking.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct http_event);
} event_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MB */
} events SEC(".maps");

// slot_cb is called by bpf_loop once per slot index (0-7) within a single
// Swiss tables group.  It reads the key/value pair at that slot and appends
// it to the event scratch if the slot is occupied.
static long slot_cb(__u32 si, void *data)
{
	struct slot_ctx *c = data;

	struct http_event *ev = bpf_map_lookup_elem(&event_scratch_map, &c->map_key);
	if (!ev)
		return 1;

	// Read nh from the map value so the verifier sees a bounded scalar,
	// not a concrete accumulated stack value that forces re-verification.
	__u64 nh = ev->nheaders;
	if (nh >= MAX_HEADERS)
		return 1;

	__u8 ctrl = 0;
	bpf_probe_read_user(&ctrl, 1, (void *)(c->group_base + si));
	if (!CTRL_FULL(ctrl))
		return 0;

	__u64 sb = c->group_base + 8 + (__u64)si * SLOT_SIZE;

	__u64 kptr = 0, klen = 0;
	bpf_probe_read_user(&kptr, 8, (void *)sb);
	bpf_probe_read_user(&klen, 8, (void *)(sb + 8));
	if (!kptr || !klen || klen >= MAX_HDR_KEY)
		return 0;

	__u32 n  = (__u32)nh & (MAX_HEADERS - 1);
	__u32 kl = klen & (MAX_HDR_KEY - 1);
	bpf_probe_read_user(ev->keys[n], kl, (void *)kptr);
	ev->keys[n][kl] = '\0';

	__u64 vsp = 0, vsl = 0;
	bpf_probe_read_user(&vsp, 8, (void *)(sb + ELEM_OFF));
	bpf_probe_read_user(&vsl, 8, (void *)(sb + ELEM_OFF + 8));
	ev->vals[n][0] = '\0';
	if (vsp && vsl) {
		__u64 vptr = 0, vlen = 0;
		bpf_probe_read_user(&vptr, 8, (void *)vsp);
		bpf_probe_read_user(&vlen, 8, (void *)(vsp + 8));
		if (vptr && vlen && vlen < MAX_HDR_VAL) {
			__u32 vl = vlen & (MAX_HDR_VAL - 1);
			bpf_probe_read_user(ev->vals[n], vl, (void *)vptr);
			ev->vals[n][vl] = '\0';
		}
	}
	ev->nheaders = nh + 1;
	return 0;
}

// group_cb is called once per group index within one table.
// nh is not tracked here; slot_cb maintains it in event_scratch_map.
static long group_cb(__u32 gi, void *data)
{
	struct group_ctx *gc = data;
	struct slot_ctx sctx = {
		.group_base = gc->groups_data + (__u64)gi * GROUP_SIZE,
		.map_key    = 0,
	};
	bpf_loop(8, slot_cb, &sctx, 0);
	return 0;
}

// dir_cb is called once per directory entry.  It reads the table pointer,
// deduplicates by table.index, then sweeps its groups via group_cb.
// nh is not tracked here; slot_cb maintains it in event_scratch_map.
static long dir_cb(__u32 di, void *data)
{
	struct dir_ctx *dc = data;

	__u64 tptr = 0;
	bpf_probe_read_user(&tptr, 8, (void *)(dc->dir_ptr + (__u64)di * 8));
	if (!tptr)
		return 0;

	__s64 tidx = -1;
	bpf_probe_read_user(&tidx, 8, (void *)(tptr + TABLE_INDEX_OFF));
	if (tidx != (__s64)di)
		return 0;

	__u64 gdata = 0, gmask = 0;
	bpf_probe_read_user(&gdata, 8, (void *)(tptr + TABLE_GROUPS_DATA_OFF));
	bpf_probe_read_user(&gmask, 8, (void *)(tptr + TABLE_GROUPS_MASK_OFF));
	if (!gdata)
		return 0;

	__u32 n_groups = (gmask < 16) ? (__u32)(gmask + 1) : 16;
	struct group_ctx gctx = { .groups_data = gdata };
	bpf_loop(n_groups, group_cb, &gctx, 0);
	return 0;
}

// parse_header_cb reads the Swiss tables header map and stores up to MAX_HEADERS
// key/value pairs in event_scratch.  Called via bpf_loop(1, ...) from
// handle_uprobe so the verifier sees a fresh register state here rather than
// the accumulated branch state from the five string-field reads above.
static long parse_header_cb(__u32 unused, void *data)
{
	struct parse_hdr_ctx *pc = data;

	__u64 dir_ptr = 0, dir_len = 0;
	bpf_probe_read_user(&dir_ptr, 8, (void *)(pc->header_map + MAP_DIRPTR_OFF));
	bpf_probe_read_user(&dir_len, 8, (void *)(pc->header_map + MAP_DIRLEN_OFF));

	if (dir_len == 0 && dir_ptr) {
		struct slot_ctx sctx = { .group_base = dir_ptr, .map_key = 0 };
		bpf_loop(8, slot_cb, &sctx, 0);
	} else if (dir_ptr) {
		__u32 n_dirs = (dir_len < 16) ? (__u32)dir_len : 16;
		struct dir_ctx dctx = { .dir_ptr = dir_ptr };
		bpf_loop(n_dirs, dir_cb, &dctx, 0);
	}
	return 0;
}

SEC("uprobe/net_http_client_do")
int handle_uprobe(struct pt_regs *ctx)
{
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	off_table_t *ot = bpf_map_lookup_elem(&go_offsets_map, &pid);
	if (!ot)
		return 0;

	__u32 zero = 0;
	struct str_scratch *s = bpf_map_lookup_elem(&str_scratch_map, &zero);
	if (!s)
		return 0;

	struct http_event *scratch = bpf_map_lookup_elem(&event_scratch_map, &zero);
	if (!scratch)
		return 0;

	__u64 req = ctx->rbx;

	// Read request-line string fields into per-CPU scratch buffers.
	// Explicit null-termination because bpf_probe_read_user doesn't add it.
	__u64 method_ptr = 0, method_len = 0;
	bpf_probe_read_user(&method_ptr, 8, (void *)(req + ot->request_method));
	bpf_probe_read_user(&method_len, 8, (void *)(req + ot->request_method + 8));
	if (method_ptr && method_len < MAX_STR) {
		bpf_probe_read_user(s->method, method_len, (void *)method_ptr);
		s->method[method_len & (MAX_STR - 1)] = '\0';
	} else {
		s->method[0] = '\0';
	}

	__u64 url_ptr = 0;
	bpf_probe_read_user(&url_ptr, 8, (void *)(req + ot->request_url));

	__u64 scheme_ptr = 0, scheme_len = 0;
	bpf_probe_read_user(&scheme_ptr, 8, (void *)(url_ptr + ot->url_scheme));
	bpf_probe_read_user(&scheme_len, 8, (void *)(url_ptr + ot->url_scheme + 8));
	if (scheme_ptr && scheme_len < MAX_STR) {
		bpf_probe_read_user(s->scheme, scheme_len, (void *)scheme_ptr);
		s->scheme[scheme_len & (MAX_STR - 1)] = '\0';
	} else {
		s->scheme[0] = '\0';
	}

	__u64 host_ptr = 0, host_len = 0;
	bpf_probe_read_user(&host_ptr, 8, (void *)(url_ptr + ot->url_host));
	bpf_probe_read_user(&host_len, 8, (void *)(url_ptr + ot->url_host + 8));
	if (host_ptr && host_len < MAX_STR) {
		bpf_probe_read_user(s->host, host_len, (void *)host_ptr);
		s->host[host_len & (MAX_STR - 1)] = '\0';
	} else {
		s->host[0] = '\0';
	}

	__u64 path_ptr = 0, path_len = 0;
	bpf_probe_read_user(&path_ptr, 8, (void *)(url_ptr + ot->url_path));
	bpf_probe_read_user(&path_len, 8, (void *)(url_ptr + ot->url_path + 8));
	if (path_ptr && path_len < MAX_STR) {
		bpf_probe_read_user(s->path, path_len, (void *)path_ptr);
		s->path[path_len & (MAX_STR - 1)] = '\0';
	} else {
		s->path[0] = '\0';
	}

	__u64 query_ptr = 0, query_len = 0;
	bpf_probe_read_user(&query_ptr, 8, (void *)(url_ptr + ot->url_rawquery));
	bpf_probe_read_user(&query_len, 8, (void *)(url_ptr + ot->url_rawquery + 8));
	if (query_ptr && query_len < MAX_STR) {
		bpf_probe_read_user(s->query, query_len, (void *)query_ptr);
		s->query[query_len & (MAX_STR - 1)] = '\0';
	} else {
		s->query[0] = '\0';
	}

	// Stage the event in per-CPU scratch so slot_cb can reach it via map
	// lookup without needing the ring buffer pointer in the bpf_loop context.
	__builtin_memcpy(scratch->method, s->method, MAX_STR);
	__builtin_memcpy(scratch->scheme, s->scheme, MAX_STR);
	__builtin_memcpy(scratch->host,   s->host,   MAX_STR);
	__builtin_memcpy(scratch->path,   s->path,   MAX_STR);
	__builtin_memcpy(scratch->query,  s->query,  MAX_STR);
	scratch->nheaders = 0;

	// Read Request.Header (map[string][]string) via Go 1.24+ Swiss tables.
	// parse_header_cb is wrapped in bpf_loop(1,...) so the verifier processes
	// the Swiss tables traversal with a fresh register state.
	__u64 header_map = 0;
	bpf_probe_read_user(&header_map, 8, (void *)(req + ot->request_header));

	if (header_map) {
		struct parse_hdr_ctx pctx = { .header_map = header_map };
		bpf_loop(1, parse_header_cb, &pctx, 0);
	}

	bpf_ringbuf_output(&events, scratch, sizeof(*scratch), 0);
	return 0;
}
