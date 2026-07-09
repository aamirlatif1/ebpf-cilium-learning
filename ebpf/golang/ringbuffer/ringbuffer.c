//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	__u64 id   = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
