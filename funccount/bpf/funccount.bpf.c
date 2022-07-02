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

struct exectrace_event {
	u32 pid;
	char comm[TASK_COMM_LEN];
	unsigned char ts[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 8192);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} exectrace_pb SEC(".maps");

struct stacktrace_event _stacktrace_event = {};
struct exectrace_event _exectrace_event= {};

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct exectrace_event);
	__type(value, int);
} exectime SEC(".maps");

int self_pid = 0;
int target_pid = 0;
int trace_type = 0;

int do_stack_trace(struct pt_regs *ctx) {
	struct stacktrace_event key;
	u64 *val, one = 1;
	int pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = 0;

	if (pid == self_pid)
		return 0;

	if (target_pid >= 0 && pid != target_pid)
		return 0;

	if (trace_type == 1) 
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

int do_exec_trace(struct pt_regs *ctx) {
	struct exectrace_event ekey;
	int one = 1;
	int pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = 0;

	if (pid == self_pid)
		return 0;

	if (target_pid > 0 && pid != target_pid)
		return 0;

	if (trace_type == 0) 
		return 0;

	ekey.pid = pid;
	bpf_get_current_comm(&ekey.comm, sizeof(ekey.comm));
	ts = bpf_ktime_get_ns();


	__builtin_memcpy(&ekey.ts, &ts, sizeof(ts));
	bpf_map_update_elem(&exectime, &ekey, &one, BPF_NOEXIST);

	return 0;
}

int do_pid_trace(void *ctx) {
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == self_pid)
		return 0;

	if (target_pid > 0 && pid != target_pid)
		return 0;

	
	bpf_perf_event_output(ctx,
			&exectrace_pb,
			BPF_F_CURRENT_CPU,
			&pid,
			sizeof(pid));

	return 0;
}

SEC("tp/")
int stacktrace_tp(void *ctx)
{
	do_stack_trace(ctx);
	do_exec_trace(ctx);
	do_pid_trace(ctx);
}

SEC("kprobe/")
int stacktrace_kb(void *ctx)
{
	do_stack_trace(ctx);
	do_exec_trace(ctx);
	do_pid_trace(ctx);
}

SEC("uprobe/")
int stacktrace_ub(void *ctx)
{
	do_stack_trace(ctx);
	do_exec_trace(ctx);
	do_pid_trace(ctx);
}
