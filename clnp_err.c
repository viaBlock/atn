/*
 * ATN		CLNP error module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		2008/04/01:
 *				Fix a memory leak in clnp_emit_er() because
 *				our_addr, skb_err->data, and skb_err were not
 *				freed
 *				2008/04/06:
 *				Replace all invocation of masking() with
 *				(& CNF_*)
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/clnp.h>

void clnp_emit_er (struct sk_buff *skb, __u8 reason)
{
	__u8 type = 0;
	__u8 sp = 0;
	__u8 ms = 0;
	int idx_opt = 0;
	int idx_data = 0;
	int opt_len = 0;
	int opt_exist = 0;
	int idx_err_code = 0;
	int idx_err_len = 0;
	int idx_err_type = 0;
	int idx_err_field = 0;
	unsigned short seglen = 0;
	unsigned short hdrlen = 0;
	unsigned char *seglenPtr = NULL;
	__u8 *our_addr = NULL;
	struct sk_buff *skb_err = NULL;

	type = skb->nh.clnph->cnf_flag & CNF_TYPE;
	sp = skb->nh.clnph->cnf_flag & CNF_SP;
	ms = skb->nh.clnph->cnf_flag & CNF_MS;
	opt_exist = 0;

	/* check whether the error PDU is an Error Report PDU */
	if(type == CLNP_ER) {
		return;
	}

	/* compose a new error report */
	skb_err = (struct sk_buff *) kmalloc(sizeof(struct sk_buff),
								    GFP_KERNEL);

	/* check whether segmentation part and/or optional part exist in the
								    error PDU */
	if (skb->nh.raw[IDX_HDR_LEN] > MIN_HDR_LEN) {
		/* check whether segmentation part exist in the error PDU */
		if (sp) {
			/* check whether optional part exist in the error PDU */
			if (skb->nh.raw[IDX_HDR_LEN] > (MIN_HDR_LEN + 6)) {
				opt_exist = 1;
				idx_opt = MIN_HDR_LEN + 6;
				opt_len = skb->nh.raw[IDX_HDR_LEN] - MIN_HDR_LEN
									    - 6;
			}
		} else {
			opt_exist = 1;
			idx_opt = MIN_HDR_LEN;
			opt_len = skb->nh.raw[IDX_HDR_LEN] - MIN_HDR_LEN;
		}
	} else {
		opt_len = 0;
	}

	/* header length of Error Report PDU is the total length of
				fixed + address + option + reason for discard */
	hdrlen = (unsigned short) (MIN_HDR_LEN + opt_len + REASON_LEN);

	/* total length of ER PDU equals header length + data (header of the
							       discarded PDU) */
	seglen = (unsigned short) (hdrlen + skb->nh.raw[IDX_HDR_LEN]);

	skb_err->data = (unsigned char *) kmalloc(sizeof(unsigned char)
						  * (seglen + 100), GFP_KERNEL);

	skb_err->nh.raw = skb_err->data;
	skb_err->nh.raw[IDX_PROTO_ID] = NLPID;
	skb_err->nh.raw[IDX_HDR_LEN] = hdrlen;
	skb_err->nh.raw[IDX_VERS] = CLNPVERSION;
	skb_err->nh.raw[IDX_TTL] = CLNP_TTL_UNITS;
	skb_err->nh.raw[IDX_FLAG] = set_flag(0, 0, 0, CLNP_ER);

	seglenPtr = (unsigned char *) &seglen;

#if defined(__LITTLE_ENDIAN_BITFIELD)
	skb_err->nh.raw[IDX_SEGLEN_MSB] = seglenPtr[1];
	skb_err->nh.raw[IDX_SEGLEN_LSB] = seglenPtr[0];
#elif defined(__BIG_ENDIAN_BITFIELD)
	skb_err->nh.raw[IDX_SEGLEN_MSB] = seglenPtr[0];
	skb_err->nh.raw[IDX_SEGLEN_LSB] = seglenPtr[1];
#else
#error Only handle little and big endian byte-orders
#endif

	skb_err->nh.raw[IDX_CKSUM_MSB] = 0;
	skb_err->nh.raw[IDX_CKSUM_LSB] = 0;

	skb_err->nh.raw[IDX_DEST_LEN] = skb->nh.raw[IDX_SRC_LEN];
	memcpy(&(skb_err->nh.raw[IDX_DEST_ADDR]), &(skb->nh.raw[IDX_SRC_ADDR]),
						      skb->nh.raw[IDX_SRC_LEN]);

	skb_err->nh.raw[IDX_SRC_LEN] = CLNP_ADDR_LEN;
	our_addr = (__u8 *) kmalloc(sizeof(__u8) * CLNP_ADDR_LEN, GFP_KERNEL);
	get_nsap_addr(our_addr);
	memcpy(&(skb_err->nh.raw[IDX_SRC_ADDR]), &(our_addr[0]),
						  skb_err->nh.raw[IDX_SRC_LEN]);
	if (opt_exist) {
		memcpy(&(skb_err->nh.raw[IDX_NEXT_HDR]), &(skb->nh.raw[idx_opt])
								     , opt_len);
		idx_err_code = MIN_HDR_LEN + opt_len;
	} else {
		idx_err_code = MIN_HDR_LEN;
	}

	idx_err_len = idx_err_code + 1;
	idx_err_type = idx_err_len + 1;
	idx_err_field = idx_err_type + 1;
	skb_err->nh.raw[idx_err_code] = REASON_DISCARD;
	skb_err->nh.raw[idx_err_len] = 2;
	skb_err->nh.raw[idx_err_type] = reason;
	skb_err->nh.raw[idx_err_field] = 0;
	clnp_gen_csum(skb_err, skb_err->nh.raw[IDX_HDR_LEN]);
	idx_data = idx_err_field + 1;
	memcpy(&(skb_err->data[idx_data]), &(skb->nh.raw[IDX_PROTO_ID])
						    , skb->nh.raw[IDX_HDR_LEN]);

	printk(KERN_INFO "Error report PDU\n");

	kfree(our_addr);
	kfree(skb_err->data);
	kfree(skb_err);
}

void clnp_discard(struct sk_buff *skb, __u8 reason)
{
	__u8 type = 0;
	__u8 er = 0;
	__u16 len = 0;

	printk(KERN_INFO "Entering clnp_discard()\n");
	type = er = 0;
	len = merge_chars_to_short(skb->nh.raw[IDX_SEGLEN_MSB],
						   skb->nh.raw[IDX_SEGLEN_LSB]);

	if (skb != NULL) {
		if(len >= skb->nh.raw[IDX_HDR_LEN]) {
			type = skb->nh.clnph->cnf_flag & CNF_TYPE;
			er = skb->nh.clnph->cnf_flag & CNF_ER;

			if ((type != CLNP_ER) && er) {
				printk(KERN_INFO "Emit an Error Report PDU \n");
				clnp_emit_er(skb, reason);
			} else {
				printk(KERN_INFO "No error report generated\n");
			}
		}

		kfree(skb->nh.clnph);
		kfree_skb(skb);
		printk(KERN_INFO "PDU Discarded\n");
	}
}
