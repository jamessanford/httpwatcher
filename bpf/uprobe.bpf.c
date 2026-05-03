// SPDX-License-Identifier: GPL-2.0

// Uprobe on net/http.(*Client).do
//
// Go 1.17+ register ABI (amd64):
//   integer args: AX, BX, CX, DI, SI, R8, R9, R10, R11
//   (*Client).do(receiver *Client, req *Request, ...)
//     AX = receiver *Client  (ignored here)
//     BX = req *Request
//
// net/http.Request layout (amd64, offsets in bytes):
//   0  : Method string  { ptr uint64, len uint64 }
//   16 : URL *url.URL
//
// net/url.URL layout (amd64, offsets in bytes):
//   0  : Scheme string  { ptr, len }
//   16 : Opaque string  { ptr, len }
//   32 : User *Userinfo
//   40 : Host string    { ptr uint64, len uint64 }
//   56 : Path string    { ptr uint64, len uint64 }

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
#define MSG_SIZE 224  /* "Method=<64> Host=<64> Path=<64> + separators, null-terminated" */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16); /* 64 KB */
} events SEC(".maps");

SEC("uprobe/net_http_client_do")
int handle_uprobe(struct pt_regs *ctx)
{
	// BX holds *Request (second integer register = first non-receiver arg)
	__u64 req = ctx->rbx;

	// Read Method string header: ptr at offset 0, len at offset 8
	__u64 method_ptr = 0;
	__u64 method_len = 0;
	bpf_probe_read_user(&method_ptr, sizeof(method_ptr), (void *)req);
	bpf_probe_read_user(&method_len, sizeof(method_len), (void *)(req + 8));

	char method[MAX_STR] = {};
	if (method_len >= MAX_STR)
		method_len = MAX_STR - 1;
	bpf_probe_read_user(method, method_len, (void *)method_ptr);

	// Read URL *url.URL pointer at offset 16
	__u64 url_ptr = 0;
	bpf_probe_read_user(&url_ptr, sizeof(url_ptr), (void *)(req + 16));

	// Read URL.Host string header: ptr at offset 40, len at offset 48
	__u64 host_ptr = 0;
	__u64 host_len = 0;
	bpf_probe_read_user(&host_ptr, sizeof(host_ptr), (void *)(url_ptr + 40));
	bpf_probe_read_user(&host_len, sizeof(host_len), (void *)(url_ptr + 48));

	char host[MAX_STR] = {};
	if (host_len >= MAX_STR)
		host_len = MAX_STR - 1;
	bpf_probe_read_user(host, host_len, (void *)host_ptr);

	// Read URL.Path string header: ptr at offset 56, len at offset 64
	__u64 path_ptr = 0;
	__u64 path_len = 0;
	bpf_probe_read_user(&path_ptr, sizeof(path_ptr), (void *)(url_ptr + 56));
	bpf_probe_read_user(&path_len, sizeof(path_len), (void *)(url_ptr + 64));

	char path[MAX_STR] = {};
	if (path_len >= MAX_STR)
		path_len = MAX_STR - 1;
	bpf_probe_read_user(path, path_len, (void *)path_ptr);

	// Reserve a ring buffer slot and write "Method=<m> Host=<h> Path=<p>\0"
	char *msg = bpf_ringbuf_reserve(&events, MSG_SIZE, 0);
	if (!msg)
		return 0;

	// BPF_SNPRINTF writes into the reserved slot directly.
	BPF_SNPRINTF(msg, MSG_SIZE, "Method=%s Host=%s Path=%s", method, host, path);

	bpf_ringbuf_submit(msg, 0);
	return 0;
}
