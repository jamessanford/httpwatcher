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

// Keyed by PID (TGID); populated by Go before each uprobe is attached.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, off_table_t);
} go_offsets_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct str_scratch);
} str_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MB */
} events SEC(".maps");

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

	struct http_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	__builtin_memcpy(ev->method, s->method, MAX_STR);
	__builtin_memcpy(ev->scheme, s->scheme, MAX_STR);
	__builtin_memcpy(ev->host,   s->host,   MAX_STR);
	__builtin_memcpy(ev->path,   s->path,   MAX_STR);
	__builtin_memcpy(ev->query,  s->query,  MAX_STR);
	ev->nheaders = 0;

	// Read Request.Header (map[string][]string) via Go 1.24+ Swiss tables.
	__u64 header_map = 0;
	bpf_probe_read_user(&header_map, 8, (void *)(req + ot->request_header));

	__u32 nh = 0;
	if (!header_map)
		goto emit;

	// TODO: Swiss tables map iteration exceeds the BPF 1M-instruction verifier
	// limit with the current triple-nested loop structure.  Skip header parsing
	// until we implement a tail-call or itermap-based approach.
	goto emit;

	__u64 dir_ptr = 0, dir_len = 0;
	bpf_probe_read_user(&dir_ptr, 8, (void *)(header_map + MAP_DIRPTR_OFF));
	bpf_probe_read_user(&dir_len, 8, (void *)(header_map + MAP_DIRLEN_OFF));

	if (dir_len == 0 && dir_ptr) {
		// Small map: dirPtr → single group (≤8 entries, no tombstones).
		for (int si = 0; si < 8 && nh < MAX_HEADERS; si++) {
			__u8 ctrl = 0;
			bpf_probe_read_user(&ctrl, 1, (void *)(dir_ptr + si));
			if (!CTRL_FULL(ctrl))
				continue;

			__u64 sb = dir_ptr + 8 + (__u64)si * SLOT_SIZE;
			__u64 kptr = 0, klen = 0;
			bpf_probe_read_user(&kptr, 8, (void *)sb);
			bpf_probe_read_user(&klen, 8, (void *)(sb + 8));
			if (!kptr || !klen || klen >= MAX_HDR_KEY)
				continue;

			__u32 n = nh & (MAX_HEADERS - 1);
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
			nh++;
		}
	} else if (dir_ptr) {
		// Large map: dirPtr → [dirLen]*table.
		// Iterate up to 4 directory entries (globalDepth ≤ 2).
		for (__u32 di = 0; di < 4 && di < dir_len && nh < MAX_HEADERS; di++) {
			__u64 tptr = 0;
			bpf_probe_read_user(&tptr, 8, (void *)(dir_ptr + di * 8));
			if (!tptr)
				continue;

			// Skip duplicate directory entries: table.index is the
			// canonical position; skip if this table lives elsewhere.
			__s64 tidx = -1;
			bpf_probe_read_user(&tidx, 8, (void *)(tptr + TABLE_INDEX_OFF));
			if (tidx != (__s64)di)
				continue;

			__u64 gdata = 0, gmask = 0;
			bpf_probe_read_user(&gdata, 8, (void *)(tptr + TABLE_GROUPS_DATA_OFF));
			bpf_probe_read_user(&gmask, 8, (void *)(tptr + TABLE_GROUPS_MASK_OFF));

			for (__u32 gi = 0; gi <= gmask && gi < 4 && nh < MAX_HEADERS; gi++) {
				__u64 gbase = gdata + gi * GROUP_SIZE;
				for (int si = 0; si < 8 && nh < MAX_HEADERS; si++) {
					__u8 ctrl = 0;
					bpf_probe_read_user(&ctrl, 1, (void *)(gbase + si));
					if (!CTRL_FULL(ctrl))
						continue;

					__u64 sb = gbase + 8 + (__u64)si * SLOT_SIZE;
					__u64 kptr = 0, klen = 0;
					bpf_probe_read_user(&kptr, 8, (void *)sb);
					bpf_probe_read_user(&klen, 8, (void *)(sb + 8));
					if (!kptr || !klen || klen >= MAX_HDR_KEY)
						continue;

					__u32 n = nh & (MAX_HEADERS - 1);
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
					nh++;
				}
			}
		}
	}

emit:
	ev->nheaders = nh;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}
