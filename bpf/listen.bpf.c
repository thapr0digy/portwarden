// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// TCP listener open/close probes for the host network namespace.
//   open:  fexit/inet_csk_listen_start, after the kernel has assigned the port, only on success.
//   close: fentry/inet_csk_listen_stop, which v6.8 calls only when a listener is torn down
//          (close() via __tcp_close, shutdown(SHUT_RD) via tcp_disconnect).
// Neither hook runs per connection or per packet.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

enum event_kind {
	EVENT_OPENED = 1,
	EVENT_CLOSED = 2,
};

enum counter_index {
	COUNTER_RINGBUF_RESERVE_FAILED = 0,
	COUNTER_DROPPED_FOREIGN_NETNS = 1,
	COUNTER_COUNT,
};

struct event {
	__u64 cookie;
	__u64 ts_ns;
	__u32 tgid;
	__u32 uid;
	__u32 netns;
	__u16 family;
	__u16 port; // host byte order
	__u8 addr[16];
	__u8 kind;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__type(value, struct event);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

// Set from userspace before load; the verifier treats it as a constant.
const volatile __u32 host_netns_ino = 0;

static __always_inline void count(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&counters, &index);

	if (value)
		*value += 1; // per-CPU slot: no atomics needed
}

// Reserves and fills the fields common to both kinds, or returns NULL when the
// socket is not a host-netns TCP socket or the ring buffer is full.
static __always_inline struct event *reserve_event(struct sock *sk, __u8 kind)
{
	struct event *e;
	__u32 netns;

	if (sk->sk_protocol != IPPROTO_TCP)
		return NULL;

	netns = sk->__sk_common.skc_net.net->ns.inum;
	if (netns != host_netns_ino) {
		count(COUNTER_DROPPED_FOREIGN_NETNS);
		return NULL;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(COUNTER_RINGBUF_RESERVE_FAILED);
		return NULL;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->cookie = bpf_get_socket_cookie(sk);
	e->ts_ns = bpf_ktime_get_ns();
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->netns = netns;
	e->kind = kind;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("fexit/inet_csk_listen_start")
int BPF_PROG(on_listen, struct sock *sk, int ret)
{
	struct event *e;
	__u16 family;
	int i;

	if (ret != 0)
		return 0;

	e = reserve_event(sk, EVENT_OPENED);
	if (!e)
		return 0;

	e->uid = (__u32)bpf_get_current_uid_gid();
	family = sk->__sk_common.skc_family;
	e->family = family;
	e->port = sk->__sk_common.skc_num;
	if (family == AF_INET6) {
		for (i = 0; i < 16; i++)
			e->addr[i] = sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8[i];
	} else {
		__be32 v4 = sk->__sk_common.skc_rcv_saddr;

		__builtin_memcpy(e->addr, &v4, sizeof(v4));
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// The port and address are already released here (__inet_put_port zeroes inet_num
// before this runs), so a close carries only the cookie and the process.
SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(on_stop, struct sock *sk)
{
	struct event *e = reserve_event(sk, EVENT_CLOSED);

	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
