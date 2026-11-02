// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
//
// UDP sockets for the baseline snapshot: an iter/udp program that writes one record per
// UDP socket bound to an explicit port (SOCK_BINDPORT_LOCK; autobound and port-0 sockets
// are clients). The iterator walks only its own netns (seq_file_net), which is the
// agent's, the host's. It is the only source for kernel sockets such as VXLAN's or
// WireGuard's, which have no file and so no owner record; userspace joins the rest to
// their owners by cookie.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define AF_INET6 10

// include/net/sock.h; a macro, so not in vmlinux.h.
#define SOCK_BINDPORT_LOCK 8

struct udp_socket {
	__u64 cookie;
	__u16 family;
	__u16 port; // host byte order
	__u8 addr[16];
};

// Puts struct udp_socket in the object's BTF, so bpf2go can generate it for the layout test.
const struct udp_socket *unused_udp_socket __attribute__((unused));

SEC("iter/udp")
int udp_sockets(struct bpf_iter__udp *ctx)
{
	struct udp_sock *udp_sk = ctx->udp_sk;
	struct udp_socket rec = {};
	struct sock *sk;
	int i;

	if (!udp_sk)
		return 0; // end of iteration
	sk = &udp_sk->inet.sk;
	if (!(BPF_CORE_READ_BITFIELD(sk, sk_userlocks) & SOCK_BINDPORT_LOCK))
		return 0;

	rec.cookie = bpf_get_socket_cookie(sk);
	rec.family = sk->__sk_common.skc_family;
	rec.port = sk->__sk_common.skc_num;
	if (rec.family == AF_INET6) {
		for (i = 0; i < 16; i++)
			rec.addr[i] = sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8[i];
	} else {
		__be32 v4 = sk->__sk_common.skc_rcv_saddr;

		__builtin_memcpy(rec.addr, &v4, sizeof(v4));
	}

	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
