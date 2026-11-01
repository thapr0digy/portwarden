// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// Listener owners for the baseline snapshot: a task_file iterator that walks every open
// file of every process once and writes one record per TCP listening socket it holds.
// Userspace joins the records to the inet_diag dump by socket cookie. The iterator
// visits a thread group's shared file table once (threads that share their leader's
// files are skipped), so each process is seen once per file descriptor.
//
// An MPTCP listener (Go enables MPTCP for listeners by default) listens through its
// first TCP subflow, which is the socket inet_diag lists and the listen probe reports,
// so its record carries that subflow's cookie. On 6.8 the subflow is reachable only
// through bpf_rdonly_cast (bpf_skc_to_mptcp_sock takes no BTF pointer), which yields a
// pointer bpf_get_socket_cookie refuses, so the cookie is read from the socket instead
// of assigned: it is set once inet_diag has listed the subflow or the probe has seen
// its listen(), and Snapshot dumps the listeners before running this iterator.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> // bpf_core_type_id_kernel only

extern void *bpf_rdonly_cast(const void *obj__ign, __u32 btf_id__k) __ksym;

#define AF_INET 2
#define AF_INET6 10

struct owner {
	__u64 cookie;
	__u32 tgid;
	__u32 uid;
	char comm[16];
};

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
	if (sk->__sk_common.skc_state != TCP_LISTEN)
		return 0;
	if (sk->sk_protocol == IPPROTO_TCP) {
		rec.cookie = bpf_get_socket_cookie(sk);
	} else if (sk->sk_protocol == IPPROTO_MPTCP) {
		struct mptcp_sock *msk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct mptcp_sock));
		struct sock *subflow = msk->first;

		if (!subflow)
			return 0;
		rec.cookie = subflow->__sk_common.skc_cookie.counter;
		if (!rec.cookie)
			return 0; // not yet listed nor probed: nothing could join it
	} else {
		return 0;
	}

	rec.tgid = task->tgid;
	rec.uid = task->cred->uid.val; // real uid, as bpf_get_current_uid_gid reports it
	for (i = 0; i < sizeof(rec.comm); i++)
		rec.comm[i] = task->comm[i];

	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
