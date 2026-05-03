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

#define MAX_STR  64
#define MSG_SIZE 384

// Byte offsets for Go struct fields, populated by the loader before attaching.
// Field order must match offTable in bpf_linux.go exactly.
typedef struct {
	__u64 request_method;  // net/http.Request.Method  (string header start)
	__u64 request_url;     // net/http.Request.URL     (pointer to *url.URL)
	__u64 url_scheme;      // net/url.URL.Scheme       (string header start)
	__u64 url_host;        // net/url.URL.Host         (string header start)
	__u64 url_path;        // net/url.URL.Path         (string header start)
	__u64 url_rawquery;    // net/url.URL.RawQuery     (string header start)
} off_table_t;

// Keyed by PID (TGID); populated by Go before each uprobe is attached.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, off_table_t);
} go_offsets_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("uprobe/net_http_client_do")
int handle_uprobe(struct pt_regs *ctx)
{
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	off_table_t *ot = bpf_map_lookup_elem(&go_offsets_map, &pid);
	if (!ot)
		return 0;

	// BX holds *Request (second integer register = first non-receiver arg)
	__u64 req = ctx->rbx;

	__u64 method_ptr = 0, method_len = 0;
	bpf_probe_read_user(&method_ptr, sizeof(method_ptr), (void *)(req + ot->request_method));
	bpf_probe_read_user(&method_len, sizeof(method_len), (void *)(req + ot->request_method + 8));
	char method[MAX_STR] = {};
	if (method_len >= MAX_STR) method_len = MAX_STR - 1;
	bpf_probe_read_user(method, method_len, (void *)method_ptr);

	// URL *url.URL pointer
	__u64 url_ptr = 0;
	bpf_probe_read_user(&url_ptr, sizeof(url_ptr), (void *)(req + ot->request_url));

	__u64 scheme_ptr = 0, scheme_len = 0;
	bpf_probe_read_user(&scheme_ptr, sizeof(scheme_ptr), (void *)(url_ptr + ot->url_scheme));
	bpf_probe_read_user(&scheme_len, sizeof(scheme_len), (void *)(url_ptr + ot->url_scheme + 8));
	char scheme[MAX_STR] = {};
	if (scheme_len >= MAX_STR) scheme_len = MAX_STR - 1;
	bpf_probe_read_user(scheme, scheme_len, (void *)scheme_ptr);

	__u64 host_ptr = 0, host_len = 0;
	bpf_probe_read_user(&host_ptr, sizeof(host_ptr), (void *)(url_ptr + ot->url_host));
	bpf_probe_read_user(&host_len, sizeof(host_len), (void *)(url_ptr + ot->url_host + 8));
	char host[MAX_STR] = {};
	if (host_len >= MAX_STR) host_len = MAX_STR - 1;
	bpf_probe_read_user(host, host_len, (void *)host_ptr);

	__u64 path_ptr = 0, path_len = 0;
	bpf_probe_read_user(&path_ptr, sizeof(path_ptr), (void *)(url_ptr + ot->url_path));
	bpf_probe_read_user(&path_len, sizeof(path_len), (void *)(url_ptr + ot->url_path + 8));
	char path[MAX_STR] = {};
	if (path_len >= MAX_STR) path_len = MAX_STR - 1;
	bpf_probe_read_user(path, path_len, (void *)path_ptr);

	__u64 query_ptr = 0, query_len = 0;
	bpf_probe_read_user(&query_ptr, sizeof(query_ptr), (void *)(url_ptr + ot->url_rawquery));
	bpf_probe_read_user(&query_len, sizeof(query_len), (void *)(url_ptr + ot->url_rawquery + 8));
	char query[MAX_STR] = {};
	if (query_len >= MAX_STR) query_len = MAX_STR - 1;
	bpf_probe_read_user(query, query_len, (void *)query_ptr);

	char *msg = bpf_ringbuf_reserve(&events, MSG_SIZE, 0);
	if (!msg)
		return 0;

	BPF_SNPRINTF(msg, MSG_SIZE, "Method=%s Scheme=%s Host=%s Path=%s Query=%s",
		     method, scheme, host, path, query);

	bpf_ringbuf_submit(msg, 0);
	return 0;
}
