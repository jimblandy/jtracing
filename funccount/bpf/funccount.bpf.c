// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

struct stacktrace_event {
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 kstack;
	u32 ustack;
};

struct stacktrace_event _stacktrace_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct stacktrace_event);
	__type(value, u64);
} stackcnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 1000);
} stackmap SEC(".maps");


int self_pid = 0;
int target_pid = 0;

int do_stacktrace(void *ctx) {
	struct stacktrace_event key;
	int cp;
	int zero = 0;
	u64 *val, one = 1;
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == self_pid)
		return 0;

	if (target_pid > 0 && pid != target_pid)
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.kstack = bpf_get_stackid(ctx, &stackmap, 0 | BPF_F_FAST_STACK_CMP);
	key.ustack = bpf_get_stackid(ctx, &stackmap, 0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
	if ((int)key.kstack < 0 && (int)key.ustack < 0) {
		return 0;
	}

	val = bpf_map_lookup_elem(&stackcnt, &key);
	if (val) {
		(*val)++;
	} else {
		bpf_map_update_elem(&stackcnt, &key, &one, BPF_NOEXIST);
	}

	return 0;
}

SEC("tp/")
int stacktrace_tp(void *ctx)
{
	do_stacktrace(ctx);
}

SEC("kprobe/")
int stacktrace_kb(void *ctx)
{
	do_stacktrace(ctx);
}

SEC("uprobe/")
int stacktrace_ub(void *ctx)
{
	do_stacktrace(ctx);
}
