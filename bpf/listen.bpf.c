// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// Listener open/close probes for every network namespace; each event carries the
// socket's netns inode and the calling task's cgroup id.
// TCP:
//   open:  fexit/inet_csk_listen_start, after the kernel has assigned the port, only on success.
//   close: fentry/inet_csk_listen_stop, which v6.8 calls only when a listener is torn down
//          (close() via __tcp_close, shutdown(SHUT_RD) via tcp_disconnect).
// UDP (a UDP "listener" is a socket bound to an explicit port):
//   open:  fexit/udp_lib_get_port, on success with a nonzero requested port. Explicit
//          bind() passes the requested port; autobind and bind(:0) pass 0. A post_bind
//          cgroup program that then rejects the bind leaves a false open until the next
//          recheck.
//   close: fentry/udp_lib_unhash (fentry: it zeroes inet_num), only for a socket with
//          SOCK_BINDPORT_LOCK, which bind() sets only for a nonzero port. udp_disconnect
//          never unhashes such a socket, so connect() after bind() is not a close.
// None of the hooks runs per connection or per packet; the UDP ones run once per UDP
// socket bind and close, client sockets included, and return after one field read.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define AF_INET6 10

// include/net/sock.h; a macro, so not in vmlinux.h.
#define SOCK_BINDPORT_LOCK 8

enum event_kind {
	EVENT_OPENED = 1,
	EVENT_CLOSED = 2,
};

enum counter_index {
	COUNTER_RINGBUF_RESERVE_FAILED = 0,
	COUNTER_COUNT,
};

struct event {
	__u64 cookie;
	__u64 ts_ns;
	__u64 cgroup_id;
	__u32 tgid;
	__u32 uid;
	__u32 netns;
	__u16 family;
	__u16 port; // host byte order
	__u8 addr[16];
	__u8 kind;
	__u8 proto; // IPPROTO_TCP or IPPROTO_UDP
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

static __always_inline void count(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&counters, &index);

	if (value)
		*value += 1; // per-CPU slot: no atomics needed
}

// Reserves and fills the fields common to both kinds, or returns NULL when the
// socket's protocol is not proto or the ring buffer is full.
static __always_inline struct event *reserve_event(struct sock *sk, __u8 proto, __u8 kind)
{
	struct event *e;

	if (sk->sk_protocol != proto)
		return NULL;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(COUNTER_RINGBUF_RESERVE_FAILED);
		return NULL;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->cookie = bpf_get_socket_cookie(sk);
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->netns = sk->__sk_common.skc_net.net->ns.inum;
	e->kind = kind;
	e->proto = proto;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

// Emits an OPENED event with the socket's bound address and port.
static __always_inline void emit_opened(struct sock *sk, __u8 proto)
{
	struct event *e = reserve_event(sk, proto, EVENT_OPENED);
	__u16 family;
	int i;

	if (!e)
		return;

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
}

// Emits a CLOSED event, which carries only the cookie and the process.
static __always_inline void emit_closed(struct sock *sk, __u8 proto)
{
	struct event *e = reserve_event(sk, proto, EVENT_CLOSED);

	if (e)
		bpf_ringbuf_submit(e, 0);
}

SEC("fexit/inet_csk_listen_start")
int BPF_PROG(on_listen, struct sock *sk, int ret)
{
	if (ret == 0)
		emit_opened(sk, IPPROTO_TCP);
	return 0;
}

// The port and address are already released here (__inet_put_port zeroes inet_num
// before this runs), so a close carries only the cookie and the process.
SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(on_stop, struct sock *sk)
{
	emit_closed(sk, IPPROTO_TCP);
	return 0;
}

// The address is set by __inet_bind/__inet6_bind before get_port, and skc_num is set to
// snum on success. UDP-Lite sockets also run this and are dropped by the protocol check.
SEC("fexit/udp_lib_get_port")
int BPF_PROG(on_udp_bind, struct sock *sk, unsigned short snum, unsigned int hash2_nulladdr, int ret)
{
	if (ret == 0 && snum != 0)
		emit_opened(sk, IPPROTO_UDP);
	return 0;
}

SEC("fentry/udp_lib_unhash")
int BPF_PROG(on_udp_unhash, struct sock *sk)
{
	if (BPF_CORE_READ_BITFIELD(sk, sk_userlocks) & SOCK_BINDPORT_LOCK)
		emit_closed(sk, IPPROTO_UDP);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
