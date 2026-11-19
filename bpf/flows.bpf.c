// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// Connection flows (README "Connection flows"): one small event per TCP connection this
// host's processes make or accept, and, for the ones they make, the first bytes the client
// sends, from which the agent names the service (TLS ClientHello SNI, HTTP/1.x Host). The
// agent aggregates them per window in memory; nothing here is kept beyond one ring record.
//   out:   fexit/tcp_connect, on success: the connecting process (tcp_v4_connect and
//          tcp_v6_connect call it in its context once the peer is set). The socket is then
//          marked as awaiting its first bytes.
//   in:    fexit/inet_csk_accept, on a returned socket: the accepting process. The return
//          value is read with bpf_get_func_ret, so the program does not depend on the
//          function's arguments (four before Linux 6.10, two since).
//   bytes: fentry/tcp_sendmsg, only for a socket awaiting its first bytes (one hash lookup
//          for any other send): up to HEAD_MAX bytes of the first user buffer, sent only
//          when they start like a TLS handshake record or an HTTP/1.x method, then the mark
//          is dropped. Server-first protocols (SSH, SMTP) and kernel senders send nothing.
// The ring buffer bounds what a busy host costs: a full ring drops events and counts the
// connections lost; a lost FLOW_HEAD only leaves its connection unnamed and is not counted.
// Records are submitted without waking the agent until WAKEUP_BYTES wait in the ring; the
// agent also drains it on a short timer, so a busy host costs one wakeup per many records.
// A process's first connection (by tgid, as far as known_tgids remembers) wakes the agent at
// once, so it reads a short-lived client's executable from /proc before the client exits.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define AF_INET6 10

// The first bytes read of a client's first send: enough for a ClientHello's server_name
// behind a post-quantum key share, and for an HTTP request line and Host.
#define HEAD_MAX 2048

// Waiting bytes past which a submit wakes the agent (an eighth of the ring).
#define WAKEUP_BYTES (256 * 1024)

// A TLS record of type handshake starts with this byte (RFC 8446 5.1).
#define TLS_HANDSHAKE 0x16

// The record kinds; every record starts with its cookie and kind.
enum flow_kind {
	FLOW_OUT = 1,
	FLOW_IN = 2,
	FLOW_HEAD = 3,
};

enum counter_index {
	COUNTER_RINGBUF_RESERVE_FAILED = 0,
	COUNTER_COUNT,
};

// One connection made (FLOW_OUT) or accepted (FLOW_IN). An accepted one carries no
// cookie: no first bytes are read for it.
struct flow_conn {
	__u64 cookie;
	__u32 kind;
	__u32 tgid;
	__u64 cgroup_id;
	__u16 family;
	__u16 lport; // host byte order
	__u16 rport; // host byte order
	__u16 pad;
	__u8 raddr[16];
	char comm[16];
};

// The first bytes a connection made by this host sent (FLOW_HEAD), joined to its
// flow_conn by cookie.
struct flow_head {
	__u64 cookie;
	__u32 kind;
	__u32 len;
	__u8 data[HEAD_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
	__type(value, struct flow_conn); // for bpf2go; flow_head records share the ring
} flow_events SEC(".maps");

// Sockets awaiting their first send, by address, holding the socket's cookie (an address
// reused by a new socket holds another). LRU: a socket that never sends is evicted in time;
// its connection is still counted, only unnamed.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} awaiting_head SEC(".maps");

// Processes the agent was woken for; LRU, so a busy host's churn only costs extra wakeups.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} known_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} flow_counters SEC(".maps");

// submit_flags wakes the agent only once enough records wait; it drains the rest on a timer.
static __always_inline __u64 submit_flags(void)
{
	return bpf_ringbuf_query(&flow_events, BPF_RB_AVAIL_DATA) >= WAKEUP_BYTES ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline void count(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&flow_counters, &index);

	if (value)
		*value += 1; // per-CPU slot: no atomics needed
}

// emit_conn sends one connection of sk, made or accepted by the current process.
static __always_inline int emit_conn(struct sock *sk, __u32 kind, __u64 cookie)
{
	struct flow_conn *e;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 flags;
	__u8 one = 1;

	if (family != AF_INET && family != AF_INET6)
		return 0;
	e = bpf_ringbuf_reserve(&flow_events, sizeof(*e), 0);
	if (!e) {
		count(COUNTER_RINGBUF_RESERVE_FAILED);
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->cookie = cookie;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = tgid;
	e->family = family;
	e->kind = kind;
	e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e->raddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		__be32 v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(e->raddr, &v4, sizeof(v4));
	}
	// The process's name, not the calling thread's: a thread can rename itself.
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), bpf_get_current_task_btf()->group_leader->comm);
	flags = submit_flags();
	if (!bpf_map_lookup_elem(&known_tgids, &tgid)) {
		bpf_map_update_elem(&known_tgids, &tgid, &one, BPF_ANY);
		flags = BPF_RB_FORCE_WAKEUP;
	}
	bpf_ringbuf_submit(e, flags);
	return 1;
}

SEC("fexit/tcp_connect")
int BPF_PROG(on_connect, struct sock *sk, int ret)
{
	__u64 key = (__u64)sk;
	__u64 cookie;

	if (ret != 0)
		return 0;
	cookie = bpf_get_socket_cookie(sk);
	if (!emit_conn(sk, FLOW_OUT, cookie))
		return 0;
	bpf_map_update_elem(&awaiting_head, &key, &cookie, BPF_ANY);
	return 0;
}

SEC("fexit/inet_csk_accept")
int on_accept(__u64 *ctx)
{
	__u64 ret = 0;

	// The returned socket is read through bpf_probe_read_kernel (an untyped pointer).
	if (bpf_get_func_ret(ctx, &ret) || !ret)
		return 0;
	emit_conn((struct sock *)ret, FLOW_IN, 0);
	return 0;
}

// first_buffer sets *base and *len to the first user buffer of msg, or returns 0 for a
// kernel buffer or an iterator kind it does not read.
static __always_inline int first_buffer(struct msghdr *msg, void **base, __u64 *len)
{
	__u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
	__u64 off = BPF_CORE_READ(msg, msg_iter.iov_offset);

	if (type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
		*base = BPF_CORE_READ(msg, msg_iter.ubuf) + off;
		*len = BPF_CORE_READ(msg, msg_iter.count);
		return 1;
	}
	if (type == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		__u64 iov_len = BPF_CORE_READ(iov, iov_len);

		if (off >= iov_len)
			return 0;
		*base = BPF_CORE_READ(iov, iov_base) + off;
		*len = iov_len - off;
		return 1;
	}
	return 0;
}

// starts_like_tls_or_http reports whether b opens a TLS handshake record or an HTTP/1.x
// request (a method is uppercase ASCII); anything else is never sent to the agent.
static __always_inline int starts_like_tls_or_http(__u8 b)
{
	return b == TLS_HANDSHAKE || (b >= 'A' && b <= 'Z');
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	__u64 key = (__u64)sk;
	__u64 *awaiting = bpf_map_lookup_elem(&awaiting_head, &key);
	__u64 cookie;
	struct flow_head *h;
	void *base = NULL;
	__u64 len = 0;
	__u32 n;

	if (!awaiting)
		return 0;
	cookie = bpf_get_socket_cookie(sk);
	// Only the first send is read, whatever it holds; an address reused by another
	// socket holds a stale cookie and is only dropped.
	if (*awaiting != cookie) {
		bpf_map_delete_elem(&awaiting_head, &key);
		return 0;
	}
	bpf_map_delete_elem(&awaiting_head, &key);
	if (!first_buffer(msg, &base, &len))
		return 0;
	if (len > size)
		len = size;
	n = len > HEAD_MAX ? HEAD_MAX : (__u32)len;
	if (n == 0)
		return 0;

	h = bpf_ringbuf_reserve(&flow_events, sizeof(*h), 0);
	if (!h)
		return 0;
	h->cookie = cookie;
	h->kind = FLOW_HEAD;
	h->len = n;
	if (bpf_probe_read_user(h->data, n, base) || !starts_like_tls_or_http(h->data[0])) {
		bpf_ringbuf_discard(h, 0);
		return 0;
	}
	bpf_ringbuf_submit(h, submit_flags());
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
