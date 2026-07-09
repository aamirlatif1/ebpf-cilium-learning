//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int hello(void *ctx) {
	bpf_trace_printk("Hello World!");
	return 0;
}
