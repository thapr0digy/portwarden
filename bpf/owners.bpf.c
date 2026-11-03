// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// Socket owners for the baseline snapshot: a task_file iterator that walks every open
// file of every process once and writes one record per TCP listening socket, or UDP
// socket bound to an explicit port, that it holds, in any network namespace. Each record
// carries the socket's full key (netns, proto, address, port), so userspace keys sockets
// outside the host netns from the records alone and joins host ones to the inet_diag and
// iter/udp dumps by socket cookie. The iterator visits a thread group's shared file table
// once (threads that share their leader's files are skipped), so each process is seen
// once per file descriptor.
//
// An MPTCP listener (Go enables MPTCP for listeners by default) listens through its
// first TCP subflow, which is the socket inet_diag lists and the listen probe reports,
// so its record carries that subflow's cookie and address. On 6.8 the subflow is
// reachable only through bpf_rdonly_cast (bpf_skc_to_mptcp_sock takes no BTF pointer),
// which yields a pointer bpf_get_socket_cookie refuses, so the cookie is read from the
// socket instead of assigned: it is set once inet_diag has listed the subflow or the
// probe has seen its listen(), and Snapshot dumps the listeners before running this
// iterator. That dump covers only the host netns, so an MPTCP listener elsewhere that
// neither has seen is reported under the MPTCP socket's own cookie (see the branch).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

extern void *bpf_rdonly_cast(const void *obj__ign, __u32 btf_id__k) __ksym;

#define AF_INET 2
#define AF_INET6 10

// include/net/sock.h; a macro, so not in vmlinux.h.
#define SOCK_BINDPORT_LOCK 8

struct owner {
	__u64 cookie;
	__u64 cgroup_id;
	__u32 tgid;
	__u32 uid;
	__u32 netns;
	__u16 family;
	__u8 proto; // IPPROTO_TCP (an MPTCP listener's subflow too) or IPPROTO_UDP
	__u8 v6only; // see v6only_of; in what was padding, so the layout is unchanged
	__u16 port; // host byte order
	__u8 addr[16];
	char comm[16];
};

// Puts struct owner in the object's BTF, so bpf2go can generate it for the layout test.
const struct owner *unused_owner __attribute__((unused));

// IPV6_V6ONLY as the model encodes it (model.V6Only): 0 not read (an IPv4 socket),
// 1 dual-stack, 2 v6-only. Fixed once the socket is bound.
static __always_inline __u8 v6only_of(struct sock *sk)
{
	if (sk->__sk_common.skc_family != AF_INET6)
		return 0;
	// A kernel without the field (CO-RE relocation would fail): not read.
	if (!bpf_core_field_exists(sk->__sk_common.skc_ipv6only))
		return 0;
	return BPF_CORE_READ_BITFIELD(&sk->__sk_common, skc_ipv6only) ? 2 : 1;
}

// Copies the socket's netns, family, bound port, bound address and IPV6_V6ONLY into rec.
static __always_inline void fill_key(struct owner *rec, struct sock *sk)
{
	int i;

	rec->netns = sk->__sk_common.skc_net.net->ns.inum;
	rec->family = sk->__sk_common.skc_family;
	rec->port = sk->__sk_common.skc_num;
	rec->v6only = v6only_of(sk);
	if (rec->family == AF_INET6) {
		for (i = 0; i < 16; i++)
			rec->addr[i] = sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8[i];
	} else {
		__be32 v4 = sk->__sk_common.skc_rcv_saddr;

		__builtin_memcpy(rec->addr, &v4, sizeof(v4));
	}
}

SEC("iter/task_file")
int owners(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct owner rec = {};
	struct socket *sock;
	struct sock *sk;
	__u16 family;
	int i;

	if (!task || !file)
		return 0; // end of iteration

	sock = bpf_sock_from_file(file);
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	if (sk->sk_protocol == IPPROTO_UDP) {
		if (!(BPF_CORE_READ_BITFIELD(sk, sk_userlocks) & SOCK_BINDPORT_LOCK))
			return 0; // unbound, autobound or bound to port 0: a client
		rec.cookie = bpf_get_socket_cookie(sk);
		rec.proto = IPPROTO_UDP;
		fill_key(&rec, sk);
	} else if (sk->__sk_common.skc_state != TCP_LISTEN) {
		return 0;
	} else if (sk->sk_protocol == IPPROTO_TCP) {
		rec.cookie = bpf_get_socket_cookie(sk);
		rec.proto = IPPROTO_TCP;
		fill_key(&rec, sk);
	} else if (sk->sk_protocol == IPPROTO_MPTCP) {
		struct mptcp_sock *msk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct mptcp_sock));
		struct sock *subflow = msk->first;

		if (!subflow)
			return 0;
		rec.cookie = subflow->__sk_common.skc_cookie.counter;
		// Not yet listed nor probed: a listener in a netns the host dump can't see,
		// opened while no probe ran. Report it under the MPTCP socket's own cookie, which
		// can be assigned here and comes from the same global counter, so it never
		// collides with a subflow's. The live probe reports the subflow's cookie, so this
		// listener's close (or restart) is not matched to it and the next recheck closes
		// it (a restart shows as closed + opened, not owner_changed).
		if (!rec.cookie)
			rec.cookie = bpf_get_socket_cookie(sk);
		rec.proto = IPPROTO_TCP;
		fill_key(&rec, subflow);
	} else {
		return 0;
	}

	rec.cgroup_id = task->cgroups->dfl_cgrp->kn->id;
	rec.tgid = task->tgid;
	rec.uid = task->cred->uid.val; // real uid, as bpf_get_current_uid_gid reports it
	for (i = 0; i < sizeof(rec.comm); i++)
		rec.comm[i] = task->comm[i];

	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
