// SPDX-License-Identifier: GPL-2.0
/*
 * ATN		An implementation of the ATN TP4/CLNP protocol suite for
 *		the GNU/Linux operating system.  ATN is implemented using the
 *		BSD Socket interface as the means of communication with
 *		the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	- 2007/08/04:
 *				* Register IP packet handler
 *				* Define IP packet type in af_inet.c
 *				* Call dev_add_pack() for registering IP packet
 *				handler (dev_add_pack() is defined in
 *				net/core/dev.c)
 *		Tadeus:		- 2008/03/24:
 *				* Replace the use of dev_add_pack() with
 *				register_8022_client() to handle IEEE 802.3
 *				frame
 *				- 2008/04/07:
 *				* Create a new type of BSD socket whose
 *				communication domain is PF_ATN, communication
 *				semantic is SOCK_RAW, and communication protocol
 *				is zero to enable the delivery of the payload of
 *				a CLNP datagram to a user-space program
 *				- 2008/05/27:
 *				* Complete the initial version of the PF_ATN
 *				socket without CLNP support
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <linux/version.h>
#include <asm/errno.h>
#include <asm/types.h>

#include <linux/atn.h>
#include <linux/clnp.h>
#include <linux/ctype.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <linux/etherdevice.h>

#include <net/clnp.h>
#include <net/datalink.h>
#include <net/p8022.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cast of dozens");
MODULE_AUTHOR("Anton Bondarenko");
MODULE_DESCRIPTION("The ATN TP4/CLNP Networking Suite for GNU/Linux");
MODULE_SUPPORTED_DEVICE("netdevice");

/* Private Function Prototypes */
static __always_inline struct atn_sock *atn_sk(struct sock *sk)
{
	return (struct atn_sock *)sk;
}

static int atn_rcv(struct sk_buff *skb, struct net_device *dev
			 , struct packet_type *pt, struct net_device *orig_dev);
static struct sock *lookup_clnp_sk_list(__u8 *nsap);
static int atn_create(struct net *net, struct socket *sock, int protocol, int kern);
static int atn_release(struct socket *sock);
static int atn_bind(struct socket *sock, struct sockaddr *saddr, int len);
static int atn_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);
static int atn_sendmsg(struct socket *sock, struct msghdr *msg, size_t len);
static void atn_prepend_clnphdr(struct sk_buff *skb, u8 *dst_addr, u8 *src_addr);

/* Private Global Variables */
static struct proto atn_proto = {
	.name = "ATN",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct atn_sock),
};

static struct net_proto_family atn_family_ops = {
	.family = PF_ATN,
	.create = atn_create,
	.owner = THIS_MODULE,
};

static struct proto_ops atn_sockraw_ops = {
	.family = PF_ATN,
	.owner = THIS_MODULE,
	.release = atn_release,
	.recvmsg = atn_recvmsg,
	.sendmsg = atn_sendmsg,
	.bind = atn_bind,
	.connect = sock_no_connect,
	.getname = sock_no_getname,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
#if KERNEL_VERSION(4, 18, 0) > LINUX_VERSION_CODE
	.poll = sock_no_poll,
#endif
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = sock_no_setsockopt,
	.compat_getsockopt = sock_no_getsockopt,
#endif
};

struct datalink_proto *p8022_datalink;
static const unsigned char atn_8022_type = 0xFE; /* ISO Network Layer */

static HLIST_HEAD(clnp_sk_list);
static DEFINE_RWLOCK(clnp_sk_list_lock);

static struct net_device *atn_get_dev_out(struct net *net, u8 *ha)
{
	struct net_device *dev;

	if (is_zero_ether_addr(ha)) {
		rtnl_lock();
		dev = net->loopback_dev;
		dev_hold(dev);
		rtnl_unlock();

		return dev;
	}

	rtnl_lock();
	dev = dev_getbyhwaddr_rcu(net, ARPHRD_ETHER, ha);
	if (dev)
		dev_hold(dev);
	rtnl_unlock();

	return dev;
}

static int atn_rcv(struct sk_buff *skb, struct net_device *dev,
				   struct packet_type *pt, struct net_device *orig_dev)
{
	int rc = 0;
	struct clnphdr *clnph = NULL;
	struct sock *sk = NULL;

	if (skb->pkt_type == PACKET_OTHERHOST) {
		net_warn_ratelimited("%s: received packet for another host\n", __func__);
		goto drop;
	}

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		net_err_ratelimited("%s: couldn't clone skb\n", __func__);
		goto out;
	}

	if (!pskb_may_pull(skb, CLNP_FIX_LEN)) {
		net_err_ratelimited("%s: could not retrieve CLNP header\n", __func__);
		goto drop;
	}
	skb_reset_transport_header(skb);

	clnph = clnp_hdr(skb);

	if (skb->len != ntohs(clnph->seglen)) {
		net_err_ratelimited("%s: could not retrieve CLNP seglen %d, skb->len=%d\n", __func__, (int)ntohs(clnph->seglen), skb->len);
		goto drop;
	}

	sk = lookup_clnp_sk_list(clnph->dest_addr);
	if (!sk) {
		net_err_ratelimited("%s: could not find socket in the list for dest\n", __func__);
		goto drop;
	}

	rc = sock_queue_rcv_skb(sk, skb);
	sock_put(sk);

	if (rc < 0) {
		net_err_ratelimited("%s: could not queue received skb, error %d\n", __func__, rc);
		goto drop;
	}

	goto out;

drop:
	kfree_skb(skb);
out:
	return rc;
}

static struct sock *lookup_clnp_sk_list(__u8 *nsap)
{
	struct sock *sk = NULL;
	struct sock *result = NULL;

	read_lock(&clnp_sk_list_lock);
	sk_for_each(sk, &clnp_sk_list) {
		struct atn_sock *atns = atn_sk(sk);

		if (cmp_nsap(nsap, atns->nsap.s_addr)) {
			result = sk;
			sock_hold(result);
			break;
		}
	}
	read_unlock(&clnp_sk_list_lock);

	return result;
}

static int atn_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk = NULL;

	if (sock->type != SOCK_RAW) {
		pr_err("%s: only RAW socket type supported\n", __func__);
		return -ESOCKTNOSUPPORT;
	}

	if (protocol != 0) {
		pr_err("%s: only protocol 0 supported\n", __func__);
		return -EPROTONOSUPPORT;
	}

	sk = sk_alloc(net, PF_ATN, GFP_KERNEL, &atn_proto, kern);
	if (!sk) {
		pr_err("%s: couldn't allocate sock\n", __func__);
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sock->ops = &atn_sockraw_ops;

	write_lock_bh(&clnp_sk_list_lock);
	sk_add_node(sk, &clnp_sk_list);
	write_unlock_bh(&clnp_sk_list_lock);

	return 0;
}

static int atn_release(struct socket *sock)
{
	struct sock *sk_in_list = NULL;
	struct sock *sk = sock->sk;

	if (!sk) {
		pr_warn("%s: nothing to release\n", __func__);
		return 0;
	}

	sock->sk = NULL;

	write_lock_bh(&clnp_sk_list_lock);
	sk_for_each(sk_in_list, &clnp_sk_list) {
		if (sk_in_list == sk) {
			sock_put(sk_in_list);
			__sk_del_node(sk_in_list);
		}
	}
	write_unlock_bh(&clnp_sk_list_lock);

	sock_orphan(sk);
	skb_queue_purge(&sk->sk_receive_queue);
	sock_put(sk);

	return 0;
}

static int atn_bind(struct socket *sock, struct sockaddr *saddr, int saddr_len)
{
	struct sock *sk_in_list = NULL;
	struct sock *sk = sock->sk;
	struct atn_sock *atns = atn_sk(sk);
	struct sockaddr_atn *addr = (struct sockaddr_atn *)saddr;
	int rc = -EINVAL;

	if (!sock_flag(sk, SOCK_ZAPPED) || saddr_len != sizeof(*addr)) {
		pr_err("%s: could not bind socket, SOCK_ZAPPED=%d, addr_len=%d\n",
			   __func__, sock_flag(sk, SOCK_ZAPPED), saddr_len);
		goto out;
	}

	rc = -EADDRINUSE;
	write_lock_bh(&clnp_sk_list_lock);
	sk_for_each(sk_in_list, &clnp_sk_list) {
		struct atn_sock *atns_in_list = atn_sk(sk_in_list);

		if (atns == atns_in_list)
			continue;

		if (cmp_nsap(atns_in_list->nsap.s_addr, addr->satn_addr.s_addr)) {
			pr_err("%s: address in use\n", __func__);
			write_unlock_bh(&clnp_sk_list_lock);
			goto out;
		}
	}
	memcpy(atns->nsap.s_addr, addr->satn_addr.s_addr, NSAP_ADDR_LEN);
	ether_addr_copy(atns->snpa, addr->satn_mac_addr);
	write_unlock_bh(&clnp_sk_list_lock);

	sock_reset_flag(sk, SOCK_ZAPPED);
	rc = 0;

out:
	return rc;
}

static int atn_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_atn *satn = (struct sockaddr_atn *)msg->msg_name;
	struct clnphdr *clnph = NULL;
	struct sk_buff *skb;
	int copied;
	int rc;

	rc = -ENOTCONN;
	if (sock_flag(sk, SOCK_ZAPPED)) {
		net_err_ratelimited("%s: socket not bind\n", __func__);
		goto out;
	}

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT, &rc);
	if (!skb) {
		net_err_ratelimited("%s: couldn't receive\n", __func__);
		goto out;
	}

	clnph = clnp_hdr(skb);
	copied = ntohs(clnph->seglen) - clnph->hdrlen;
	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}

	rc = skb_copy_datagram_msg(skb, clnph->hdrlen, msg, copied);
	if (rc) {
		net_err_ratelimited("%s: couldn't copy datagram data\n", __func__);
		goto out_free;
	}
	sock_recv_timestamp(msg, sk, skb);

	msg->msg_namelen = sizeof(*satn);

	if (satn) {
		satn->satn_family = AF_ATN;
		memcpy(&satn->satn_addr.s_addr, clnph->src_addr, clnph->src_len);
		memcpy(satn->satn_mac_addr, eth_hdr(skb)->h_source, ETH_ALEN);
	}
	rc = copied;

out_free:
	skb_free_datagram(sk, skb);
out:
	return rc;
}

static int atn_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct atn_sock *atns = atn_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_atn *, usatn, msg->msg_name);
	int rc = -ENOTCONN;
	int flags = msg->msg_flags;
	struct sk_buff *skb = NULL;
	struct net_device *dev;
	int total_header_len = 0;

	if (sock_flag(sk, SOCK_ZAPPED)) {
		net_err_ratelimited("%s: socket not bind\n", __func__);
		goto out;
	}

	rc = -EINVAL;
	if (flags & ~(MSG_DONTWAIT | MSG_CMSG_COMPAT)) {
		net_err_ratelimited("%s: socket not bind\n", __func__);
		goto out;
	}

	rc = -ENODEV;
	dev = atn_get_dev_out(sock_net(sk), atns->snpa);
	if (!dev) {
		net_err_ratelimited("%s: could not get network dev to send over\n", __func__);
		goto out;
	}

	total_header_len = dev->hard_header_len + p8022_datalink->header_length
								 + CLNP_FIX_LEN;

	rc = -EMSGSIZE;
	if (len > ETH_FRAME_LEN - total_header_len) {
		net_err_ratelimited("%s: not space for data, required %lu, available %d\n",
							__func__, len, ETH_FRAME_LEN - total_header_len);
		goto out_dev;
	}

	rc = -ENOMEM;
	skb = sock_alloc_send_skb(sk, NET_IP_ALIGN + total_header_len + len, flags & MSG_DONTWAIT, &rc);
	if (!skb) {
		net_err_ratelimited("%s: couldn't allocate skb, size %lu, error %d\n",
							__func__, NET_IP_ALIGN + total_header_len + len, rc);
		goto out_dev;
	}
	/* reserver memory for CLNP header + LLC header + dev hard header */
	skb_reserve(skb, NET_IP_ALIGN + total_header_len);

	skb->sk = sk;

	rc = memcpy_from_msg(skb_put(skb, len), msg, len);
	if (rc) {
		net_err_ratelimited("%s: couldn't copy msg of size %lu, error %d\n",
							__func__, len, rc);
		goto out_dev;
	}

	skb->dev = dev;
	skb->protocol = htons(ETH_P_802_2);

	atn_prepend_clnphdr(skb, usatn->satn_addr.s_addr, atns->nsap.s_addr);

	rc = p8022_datalink->request(p8022_datalink, skb, usatn->satn_mac_addr);

	if (rc >= 0)
		rc = len;
	else {
		net_err_ratelimited("%s: P802.2 request failed, error %d\n", __func__, rc);
		goto out_dev;
	}

out:
	return rc;

out_dev:
	if(skb)
		kfree_skb(skb);
	dev_put(dev);
	goto out;
}

static void atn_prepend_clnphdr(struct sk_buff *skb, u8 *dst_addr, u8 *src_addr)
{
	struct clnphdr *clnph;

	skb_push(skb, CLNP_FIX_LEN);
	skb_reset_transport_header(skb);

	clnph = clnp_hdr(skb);

	clnph->nlpid = CLNP_NLPID;
	clnph->hdrlen = CLNP_FIX_LEN;
	clnph->vers = CLNP_VERSION;
	clnph->ttl = 40;
	clnph->flag = set_clnp_flag(0, 0, 1, CLNP_DT);
	clnph->seglen = htons(skb->len);
	clnph->src_len = NSAP_ADDR_LEN;
	clnph->dest_len = NSAP_ADDR_LEN;
	memcpy(clnph->dest_addr, dst_addr, NSAP_ADDR_LEN);
	memcpy(clnph->src_addr, src_addr, NSAP_ADDR_LEN);

	clnp_gen_csum(clnph);
}

static int __init init_atn(void)
{
	int err = -1;

	rwlock_init(&clnp_sk_list_lock);

	do {
		err = proto_register(&atn_proto, 1);
		if (err) {
			pr_err("%s: couldn't register ATN protocol, error %d\n", __func__, err);
			break;
		}

		err = sock_register(&atn_family_ops);
		if (err) {
			pr_err("%s: couldn't register ATN socket, error %d\n", __func__, err);
			proto_unregister(&atn_proto);
			break;
		}

		p8022_datalink = register_8022_client(atn_8022_type, atn_rcv);
		if (!p8022_datalink) {
			pr_crit("%s: Unable to register with 802.2\n", __func__);
			sock_unregister(PF_ATN);
			proto_unregister(&atn_proto);
			err = -EFAULT;
			break;
		}
	} while (0);

	return err;
}
module_init(init_atn);

static void __exit cleanup_atn(void)
{
	if (p8022_datalink) {
		unregister_8022_client(p8022_datalink);
		p8022_datalink = NULL;
	}

	sock_unregister(PF_ATN);
	proto_unregister(&atn_proto);
}
module_exit(cleanup_atn);
