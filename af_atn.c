/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
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
 *				- 2008/04/15:
 *				* Complete the initial model of the receiving
 *				mechanism of the socket
 *				* Working on the initial model of the sending
 *				mechanism of the socket
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/errno.h>
#include <asm/types.h>
#include <linux/atn.h>
#include <linux/clnp.h>
#include <linux/ctype.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <net/clnp.h>
#include <net/datalink.h>
#include <net/p8022.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cast of dozens");
MODULE_DESCRIPTION("ATN protocol stack for Linux");
MODULE_SUPPORTED_DEVICE("netdevice");

/* Private Function Prototypes */
static __always_inline struct atn_sock *atn_sk(struct sock *sk)
{
	return (struct atn_sock *)sk;
}
static int atn_rcv(struct sk_buff *skb, struct net_device *dev
			 , struct packet_type *pt, struct net_device *orig_dev);
static int atn_create(struct socket *sock, int protocol);
static int atn_release(struct socket *sock);
static int atn_recvmsg(struct kiocb *iocb, struct socket *sock
				  , struct msghdr *msg, size_t size, int flags);

/* Private Global Variables */
static struct proto atn_proto = {
	.name = "ATN"
	, .owner = THIS_MODULE
	, .obj_size = sizeof(struct atn_sock)
};
static struct net_proto_family atn_family_ops = {
	.family = PF_ATN
	, .create = atn_create
	, .owner = THIS_MODULE
};
static struct proto_ops atn_sockraw_ops = {
	.family = PF_ATN
	, .owner = THIS_MODULE
	, .release = atn_release
	, .recvmsg = atn_recvmsg

	, .bind = sock_no_bind
	, .connect = sock_no_connect
	, .getname = sock_no_getname
	, .socketpair = sock_no_socketpair
	, .accept = sock_no_accept
	, .poll = sock_no_poll
	, .ioctl = sock_no_ioctl
	, .listen = sock_no_listen
	, .shutdown = sock_no_shutdown
	, .setsockopt = sock_no_setsockopt
	, .getsockopt = sock_no_getsockopt
	, .mmap = sock_no_mmap
	, .sendmsg = sock_no_sendmsg
	, .sendpage = sock_no_sendpage
};
static struct datalink_proto *p8022_datalink = NULL;
static unsigned char atn_8022_type = 0xFE; /* ISO Network Layer */
static char atn_llc_err_msg[] __initdata =
			       KERN_CRIT "ATN: Unable to register with 802.2\n";
static struct sock *sk = NULL; /* dirty hack! Use link list of sks instead */

static int __init init_atn(void)
{
	printk(KERN_INFO __FILE__": init_atn()\n");

	proto_register(&atn_proto, 1);
	sock_register(&atn_family_ops);

	p8022_datalink = register_8022_client(atn_8022_type, atn_rcv);
	if (!p8022_datalink) {
		printk(atn_llc_err_msg);
		return -1;
	}

	return 0;
}
module_init(init_atn);

static void __exit cleanup_atn(void)
{
	printk(KERN_INFO __FILE__": cleanup_atn()\n");

	if (p8022_datalink) {
		unregister_8022_client(p8022_datalink);
		p8022_datalink = NULL;
	}

	sock_unregister(PF_ATN);
	proto_unregister(&atn_proto);
}
module_exit(cleanup_atn);

static int atn_rcv(struct sk_buff *skb, struct net_device *dev
			  , struct packet_type *pt, struct net_device *orig_dev)
{
	int rc = 0;

	if (skb->pkt_type == PACKET_OTHERHOST) {
		goto drop;
	}

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct clnphdr))) {
		goto drop;
	}

	if (!pskb_may_pull(skb, clnp_hdr(skb)->cnf_hdr_len)) {
		goto drop;
	}

	if (sk == NULL) {
		goto drop;
	}

	if ((rc = sock_queue_rcv_skb(sk, skb)) < 0) {
		goto drop;
	}

drop:
	kfree_skb(skb);
out:
	return rc;
}

void get_nsap_addr(__u8 *addr)
{
	addr[0] = 0x47;
	addr[1] = 0x00;
	addr[2] = 0x27;
	addr[3] = 0x81;
	addr[4] = 0x81;
	addr[5] = 0x53;
	addr[6] = 0x47;
	addr[7] = 0x00;
	addr[8] = 0x22;
	addr[9] = 0x22;
	addr[10] = 0x22;
	addr[11] = 0x00;
	addr[12] = 0x01;
	addr[13] = 0x88;
	addr[14] = 0x88;
	addr[15] = 0x88;
	addr[16] = 0x88;
	addr[17] = 0x88;
	addr[18] = 0x77;
	addr[19] = 0x00;
}

static int atn_create(struct socket *sock, int protocol)
{
	/* struct sock *sk = NULL; uncomment after dirty hack is removed */

	if (sock->type != SOCK_RAW) {
		return -ESOCKTNOSUPPORT;
	}

	if (protocol != 0) {
		return -EPROTONOSUPPORT;
	}

	sk = sk_alloc(PF_ATN, GFP_KERNEL, &atn_proto, 1);
	if (!sk) {
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sock->ops = &atn_sockraw_ops;
	sock_reset_flag(sk, SOCK_ZAPPED);

	return 0;
}

static int atn_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk) {
		return 0;
	}

	sock_orphan(sk);
	sock->sk = NULL;
	skb_queue_purge(&sk->sk_receive_queue);
	sock_put(sk);

	return 0;
}

static int atn_recvmsg(struct kiocb *iocb, struct socket *sock
				   , struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_atn *satn = (struct sockaddr_atn *) msg->msg_name;
	struct clnphdr *clnph = NULL;
	struct sk_buff *skb;
	int copied;
	int rc;

	rc = -ENOTCONN;
	if (sock_flag(sk, SOCK_ZAPPED)) {
		goto out;
	}

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT
									 , &rc);
	if (!skb) {
		goto out;
	}

	clnph = clnp_hdr(skb);
	copied = -clnph->cnf_hdr_len;
	copied -= clnph->cnf_flag & CNF_SP ? 6 : 0;
	copied += ntohs(clnph->cnf_seglen);
	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}

	rc = skb_copy_datagram_iovec(skb, clnph->cnf_hdr_len, msg->msg_iov
								      , copied);
	if (rc) {
		goto out_free;
	}
	if (skb->tstamp.off_sec) {
		skb_get_timestamp(skb, &sk->sk_stamp);
	}

	msg->msg_namelen = sizeof(*satn);

	if (satn) {
		satn->satn_family = AF_ATN;
		memcpy(&satn->satn_addr.s_addr, clnph->src_addr, clnph->src_len)
									       ;
	}
	rc = copied;

out_free:
	skb_free_datagram(sk, skb);
out:
	return rc;
}
