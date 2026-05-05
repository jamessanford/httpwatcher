// go:build ignore
//  +build ignore

// SPDX-License-Identifier: GPL-2.0

// Uprobe on net/http.(*Client).do
//
// Go 1.17+ register ABI (amd64):
//   integer args: AX, BX, CX, DI, SI, R8, R9, R10, R11
//   (*Client).do(receiver *Client, req *Request, ...)
//     AX = receiver *Client  (ignored here)
//     BX = req *Request

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_STR      64   /* must be power of 2 */
#define MAX_HEADERS  16   /* must be power of 2 */
#define MAX_HDR_KEY  64   /* must be power of 2 */
#define MAX_HDR_VAL  512  /* must be power of 2 */

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

// Go ≤1.23 hmap/bmap layout for map[string][]string (amd64).
//
// runtime.hmap:
//   count      int            @ +0
//   flags      uint8          @ +8
//   B          uint8          @ +9   log2 of bucket count
//   noverflow  uint16         @ +10
//   hash0      uint32         @ +12
//   buckets    unsafe.Pointer @ +16  → *bmap array
//   oldbuckets unsafe.Pointer @ +24
//
// runtime.bmap (bucket), non-interleaved layout:
//   tophash  [8]uint8         @ +0    (8 bytes)
//   keys     [8]string        @ +8    (8×16 = 128 bytes)
//   values   [8][]string      @ +136  (8×24 = 192 bytes)
//   overflow *bmap            @ +328
//
// Slot i:  key ptr   @ +8   + i*16
//          key len   @ +16  + i*16
//          val ptr   @ +136 + i*24
//          val len   @ +144 + i*24
#define HMAP_B_OFF            9
#define HMAP_BUCKETS_OFF      16
#define HMAP_BUCKET_KEYS_OFF  8    /* first key in bucket */
#define HMAP_BUCKET_VALS_OFF  136  /* first value in bucket (8 + 8*16) */
#define HMAP_KEY_STRIDE       16   /* sizeof(string) */
#define HMAP_VAL_STRIDE       24   /* sizeof([]string) */
#define HMAP_BUCKET_SIZE      336  /* 8+128+192+8 */
#define HMAP_MIN_TOPHASH      5    /* tophash < 5 means empty/evacuated */

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
	__u64 swiss_tables; // 1 = Go 1.24+ Swiss tables, 0 = Go ≤1.23 hmap
} off_table_t;

struct http_event {
	__u64 pid;
	char  method[MAX_STR];
	char  scheme[MAX_STR];
	char  host[MAX_STR];
	char  path[MAX_STR];
	char  query[MAX_STR];
	__u64 nheaders;
	char  keys[MAX_HEADERS][MAX_HDR_KEY];
	char  vals[MAX_HEADERS][MAX_HDR_VAL];
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

// Contexts for the hmap (Go ≤1.23) parsing path, mirroring the Swiss tables
// callback chain.  nh lives in event_scratch_map for the same reason.
struct hmap_slot_ctx {
	__u64 bucket_ptr;
	__u32 map_key;
	__u32 _pad;
};
struct hmap_bucket_ctx {
	__u64 buckets_ptr;
};
struct parse_hmap_ctx {
	__u64 header_map;
};

// Keyed by PID (TGID); populated by Go before each uprobe is attached.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, off_table_t);
} go_offsets_map SEC(".maps");

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
	if (!kptr || !klen)
		return 0;

	__u32 n  = (__u32)nh & (MAX_HEADERS - 1);
	__u32 kl = (__u32)klen & (MAX_HDR_KEY - 1);  // mask before check; see read_gostr
	if (!kl)
		return 0;
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
		if (vptr && vlen) {
			__u32 vl = (__u32)vlen & (MAX_HDR_VAL - 1);  // mask before check
			if (vl) {
				bpf_probe_read_user(ev->vals[n], vl, (void *)vptr);
				ev->vals[n][vl] = '\0';
			}
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

// hmap_slot_cb reads one slot in an hmap bucket (Go ≤1.23 format).
// Keys are laid out contiguously before values, unlike the interleaved
// Swiss tables slot layout.
static long hmap_slot_cb(__u32 si, void *data)
{
	struct hmap_slot_ctx *c = data;

	struct http_event *ev = bpf_map_lookup_elem(&event_scratch_map, &c->map_key);
	if (!ev)
		return 1;

	__u64 nh = ev->nheaders;
	if (nh >= MAX_HEADERS)
		return 1;

	__u8 tophash = 0;
	bpf_probe_read_user(&tophash, 1, (void *)(c->bucket_ptr + si));
	if (tophash < HMAP_MIN_TOPHASH)
		return 0;

	__u64 kptr = 0, klen = 0;
	bpf_probe_read_user(&kptr, 8, (void *)(c->bucket_ptr + HMAP_BUCKET_KEYS_OFF + (__u64)si * HMAP_KEY_STRIDE));
	bpf_probe_read_user(&klen, 8, (void *)(c->bucket_ptr + HMAP_BUCKET_KEYS_OFF + (__u64)si * HMAP_KEY_STRIDE + 8));
	if (!kptr || !klen)
		return 0;

	__u32 n  = (__u32)nh & (MAX_HEADERS - 1);
	__u32 kl = (__u32)klen & (MAX_HDR_KEY - 1);  // mask before check; see read_gostr
	if (!kl)
		return 0;
	bpf_probe_read_user(ev->keys[n], kl, (void *)kptr);
	ev->keys[n][kl] = '\0';

	__u64 vsp = 0, vsl = 0;
	bpf_probe_read_user(&vsp, 8, (void *)(c->bucket_ptr + HMAP_BUCKET_VALS_OFF + (__u64)si * HMAP_VAL_STRIDE));
	bpf_probe_read_user(&vsl, 8, (void *)(c->bucket_ptr + HMAP_BUCKET_VALS_OFF + (__u64)si * HMAP_VAL_STRIDE + 8));
	ev->vals[n][0] = '\0';
	if (vsp && vsl) {
		__u64 vptr = 0, vlen = 0;
		bpf_probe_read_user(&vptr, 8, (void *)vsp);
		bpf_probe_read_user(&vlen, 8, (void *)(vsp + 8));
		if (vptr && vlen) {
			__u32 vl = (__u32)vlen & (MAX_HDR_VAL - 1);  // mask before check
			if (vl) {
				bpf_probe_read_user(ev->vals[n], vl, (void *)vptr);
				ev->vals[n][vl] = '\0';
			}
		}
	}
	ev->nheaders = nh + 1;
	return 0;
}

// hmap_bucket_cb sweeps the 8 slots of one bucket.
static long hmap_bucket_cb(__u32 bi, void *data)
{
	struct hmap_bucket_ctx *bc = data;
	struct hmap_slot_ctx sc = {
		.bucket_ptr = bc->buckets_ptr + (__u64)bi * HMAP_BUCKET_SIZE,
		.map_key    = 0,
	};
	bpf_loop(8, hmap_slot_cb, &sc, 0);
	return 0;
}

// parse_hmap_cb parses a Go ≤1.23 hmap.  Called via bpf_loop(1,...) for the
// same verifier-state isolation reason as parse_header_cb.
static long parse_hmap_cb(__u32 unused, void *data)
{
	struct parse_hmap_ctx *pc = data;

	__u8 B = 0;
	bpf_probe_read_user(&B, 1, (void *)(pc->header_map + HMAP_B_OFF));

	__u64 buckets = 0;
	bpf_probe_read_user(&buckets, 8, (void *)(pc->header_map + HMAP_BUCKETS_OFF));
	if (!buckets)
		return 0;

	// 1<<B buckets, capped so we stay well under the BPF instruction limit.
	__u32 nbuckets = (__u32)1 << (B & 0xf);
	if (nbuckets > 16)
		nbuckets = 16;

	struct hmap_bucket_ctx bc = { .buckets_ptr = buckets };
	bpf_loop(nbuckets, hmap_bucket_cb, &bc, 0);
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

// read_gostr reads a Go string (ptr+len at addr) into buf[0..max-1] and
// null-terminates it.  Returns 0 on success, -1 if the string is absent.
// Strings longer than max-1 bytes are silently truncated.
// max must be a power of two so the length mask is exact.
static __always_inline int read_gostr(void *addr, char *buf, __u32 max)
{
	__u64 ptr = 0, len = 0;
	bpf_probe_read_user(&ptr, 8, addr);
	bpf_probe_read_user(&len, 8, addr + 8);
	if (!ptr || !len) {
		buf[0] = '\0';
		return -1;
	}
	// Mask before any bounds check: the compiler must emit the AND instruction
	// so the BPF verifier on older kernels sees a bounded register.  If we
	// checked len >= max first, the compiler would prove the AND is a no-op
	// and optimize it away, leaving an unbounded R2 in the bytecode.
	__u32 l = (__u32)len & (max - 1);
	if (!l) {
		buf[0] = '\0';
		return -1;
	}
	bpf_probe_read_user(buf, l, (void *)ptr);
	buf[l] = '\0';
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
	struct http_event *scratch = bpf_map_lookup_elem(&event_scratch_map, &zero);
	if (!scratch)
		return 0;

	scratch->pid = pid;

	__u64 req = BPF_CORE_READ(ctx, bx);
	if (!req)
		return 0;

	read_gostr((void *)(req + ot->request_method), scratch->method, MAX_STR);

	__u64 url_ptr = 0;
	bpf_probe_read_user(&url_ptr, 8, (void *)(req + ot->request_url));

	read_gostr((void *)(url_ptr + ot->url_scheme), scratch->scheme, MAX_STR);
	read_gostr((void *)(url_ptr + ot->url_host),   scratch->host,   MAX_STR);
	read_gostr((void *)(url_ptr + ot->url_path),   scratch->path,   MAX_STR);
	read_gostr((void *)(url_ptr + ot->url_rawquery), scratch->query, MAX_STR);
	scratch->nheaders = 0;

	// Read Request.Header (map[string][]string).  Each parser is wrapped in
	// bpf_loop(1,...) so the verifier sees a fresh register state, independent
	// of the accumulated branch state from the string-field reads above.
	__u64 header_map = 0;
	bpf_probe_read_user(&header_map, 8, (void *)(req + ot->request_header));

	if (header_map) {
		if (ot->swiss_tables) {
			struct parse_hdr_ctx pctx = { .header_map = header_map };
			bpf_loop(1, parse_header_cb, &pctx, 0);
		} else {
			struct parse_hmap_ctx pctx = { .header_map = header_map };
			bpf_loop(1, parse_hmap_cb, &pctx, 0);
		}
	}

	bpf_ringbuf_output(&events, scratch, sizeof(*scratch), 0);
	return 0;
}
