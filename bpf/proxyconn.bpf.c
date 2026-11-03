// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// Observed proxy connections: cgroup/connect4 and cgroup/connect6, attached only to the
// cgroups of known proxies (so no other process runs them), count the TCP connects a
// proxy makes per destination. A connect counts when the calling process, or its parent
// (an nginx/Apache/HAProxy worker under its master), is in proxy_tgids, which the agent
// fills with each proxy's master and holders. Counts are aggregated in an LRU hash keyed
// by (proxy, destination), never one event per connection. Every connect is allowed.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1

struct conn_key {
	__u32 proxy; // the tgid found in proxy_tgids: the process itself or its parent
	__u16 family;
	__u16 port; // host byte order
	__u8 addr[16];
};

struct conn_val {
	__u64 count;
	__u64 last_ns; // bpf_ktime_get_ns of the latest connect
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} proxy_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_key);
	__type(value, struct conn_val);
} conns SEC(".maps");

// proxy_of sets *proxy to the tracked tgid of the caller or its parent.
static __always_inline int proxy_of(__u32 *proxy)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task;
	__u32 ptgid;

	if (bpf_map_lookup_elem(&proxy_tgids, &tgid)) {
		*proxy = tgid;
		return 1;
	}
	task = (struct task_struct *)bpf_get_current_task();
	ptgid = BPF_CORE_READ(task, real_parent, tgid);
	if (bpf_map_lookup_elem(&proxy_tgids, &ptgid)) {
		*proxy = ptgid;
		return 1;
	}
	return 0;
}

static __always_inline void record(struct conn_key *k)
{
	struct conn_val *v = bpf_map_lookup_elem(&conns, k);
	__u64 now = bpf_ktime_get_ns();

	if (!v) {
		struct conn_val init = {};

		// Another CPU may insert the same key first; then count on its entry.
		bpf_map_update_elem(&conns, k, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&conns, k);
		if (!v)
			return;
	}
	__sync_fetch_and_add(&v->count, 1);
	v->last_ns = now;
}

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *ctx)
{
	struct conn_key k = {};
	__u32 ip;

	if (ctx->type != SOCK_STREAM || !proxy_of(&k.proxy))
		return 1;
	k.family = AF_INET;
	k.port = bpf_ntohs((__u16)ctx->user_port);
	ip = ctx->user_ip4;
	__builtin_memcpy(k.addr, &ip, sizeof(ip));
	record(&k);
	return 1;
}

SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *ctx)
{
	struct conn_key k = {};
	__u32 w;

	if (ctx->type != SOCK_STREAM || !proxy_of(&k.proxy))
		return 1;
	k.family = AF_INET6;
	k.port = bpf_ntohs((__u16)ctx->user_port);
	// user_ip6 allows 4-byte loads only, one word at a time.
	w = ctx->user_ip6[0];
	__builtin_memcpy(&k.addr[0], &w, 4);
	w = ctx->user_ip6[1];
	__builtin_memcpy(&k.addr[4], &w, 4);
	w = ctx->user_ip6[2];
	__builtin_memcpy(&k.addr[8], &w, 4);
	w = ctx->user_ip6[3];
	__builtin_memcpy(&k.addr[12], &w, 4);
	record(&k);
	return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
