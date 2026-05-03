#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx)
{
	return 0;
}
