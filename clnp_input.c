// SPDX-License-Identifier: GPL-2.0
/*
 * ATN		CLNP input module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Danny Laidi <danny.laidi@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		- 2008/03/30:
 *				* Change the switch block in options part
 *				processing of clnp_rcv_finish() to a private
 *				function opt_part_hndlr()
 *				* Changing the use of a kmalloc() dynamically
 *				allocated temporary variable `opt', which is
 *				used to hold a parameter of the options part
 *				during options part processing of
 *				clnp_rcv_finish(), to an ordinary variable
 *				within the right scope to avoid overhead
 *				associated with kmalloc()
 *				* Change the bulk of else part in function
 *				clnp_decompose() with a single function memset()
 *				because the bulk of else part only sets clnph
 *				to zero
 *				- 2008/04/06:
 *				* Replace all invocation of masking() with
 *				(& CNF_*)
 *				- 2008/04/13:
 *				* Replace all instances of `nh' that is used to
 *				get the CLNP header part with clnp_hdr()
 *				- 2008/04/14:
 *				* Remove clnp_decompose(skb, clnph) from
 *				clnp_rcv() because its sole use, besides copying
 *				each field of the CLNP header from skb to clnph,
 *				is to perform the same thing as ntohs() when
 *				copying seglen (i.e.,
 *				clnph->seglen = ntohs(skb->seglen)) but with the
 *				following construct:
 *				#if defined(__BIG_ENDIAN_BITFIELD)
 *				...
 *				#elif defined(__LITTLE_ENDIAN_BITFIELD)
 *				...
 *				#else
 *				...
 *				#endif
 *				Another reason to remove clnp_decompose() is
 *				that there is no need to copy the CLNP header
 *				from skb because clnp_rcv() is read-only with
 *				regards to skb
 *				* Remove from clnp_rcv() the use of
 *				seg = (struct clnp_segment *) kmalloc(
 *				       sizeof(struct clnp_segment), GFP_KERNEL);
 *				because of the same reason why clnp_decompose()
 *				is removed
 *				* Remove free_mem_alloc(), which is used to free
 *				clnph and seg, because its service is rendered
 *				useless after the removal of clnp_decompose()
 *				and seg = (struct clnp_segment *) kmalloc()
 *				- 2008/04/17:
 *				* Replace `struct clnp_options opt' in
 *				clnp_rcv_finish() with
 *				`struct clnp_options *opt'
 *				- 2008/04/20:
 *				* Change clnp_rcv_finish(struct sk_buff *skb,
 *				struct clnphdr *clnph, struct clnp_segment *seg,
 *				int fas_len, int sp_flag, int ms_flag,
 *				int er_flag, int type_flag) to
 *				clnp_rcv_finish(struct sk_buff *skb) so that it
 *				is clear that the other parameters are derived
 *				from within skb
 *				* Change clnp_local_deliver(struct sk_buff *skb,
 *				struct clnphdr *clnph, struct clnp_segment *seg,
 *				int ms_flag) to
 *				clnp_local_deliver(struct sk_buff *skb) with the
 *				same reason as above
 *				* Replace `if ((type_flag != CLNP_DT)
 *						&& (type_flag != CLNP_MD)
 *						&& (type_flag != CLNP_ER)
 *						&& (type_flag != CLNP_ERQ)
 *						&& (type_flag != CLNP_ERP))'
 *				in clnp_rcv() with `switch' to make it easier to
 *				read and maintain
 *				* Add `check PDU size' block in clnp_rcv()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <net/clnp.h>

/*
 * Begin: Private function prototypes
 */

/**
 * opt_part_hndlr - a private function to be used within clnp_rcv_finish()
 * @opt: the parameter of the options part of a CLNP header to be processed
 *
 * Returns -1 if opt->code is illegal (i.e., not listed in linux/clnp.h).
 * Returns 0 if opt->code is legal.
 */
static __always_inline int opt_part_hndlr(struct clnp_options *opt);

/*
 * End: Private function prototypes
 */

static __always_inline int opt_part_hndlr(struct clnp_options *opt)
{
	switch (opt->code) {
	case CLNPOPT_PC_PAD:
		pr_info("Option: padding\n");
		break;
	case CLNPOPT_PC_SEC:
		pr_info("Option: security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		pr_info("Option: source routeing\n");
		break;
	case CLNPOPT_PC_ROR:
		pr_info("Option: recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		pr_info("Option: quality of service maintenance\n");
		break;
	case CLNPOPT_PC_PRIOR:
		pr_info("Option: priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		pr_info("Option: prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		pr_info("Option: radius scope control\n");
		break;
	default:
		pr_info("Option: unknown parameter\n");
		return -1;
	}

	return 0;
}

int clnp_addr_ck(struct clnphdr *clnph)
{
	return (clnph->dest_len == 20 && clnph->src_len == 20);
}

int clnp_rcv(struct sk_buff *skb, struct net_device *dev,
			    struct packet_type *pt, struct net_device *orig_dev)
{
	struct clnphdr *clnph = NULL;
	int clnph_hdrlen = 0;
	int pdu_size = 0;
	int err_location = 0;
	int rc = 0;

	/* check the existence of a CLNP header */
	if (!pskb_may_pull(skb, sizeof(struct clnphdr))) {
		err_location = 6;
		goto discard_incomplete;
	}
	clnph = clnp_hdr(skb);

	/* check the completeness of the datagram */
	pdu_size = ntohs(clnph->seglen);
	if (skb->len < pdu_size) {
		pr_err_ratelimited("skb len %d is less than PDU %d\n", skb->len, pdu_size);
		goto discard_incomplete;
	}

	/* check the network layer protocol ID */
	if (clnph->nlpid != CLNP_NLPID) {
		pr_err_ratelimited("CLNP header has invalid nlpid %d, should be %d\n", clnph->nlpid, CLNP_NLPID);
		rc = -NLPID_ERROR;
		goto drop;
	}

	/* check the version */
	if (clnph->vers != CLNP_VERSION) {
		pr_err_ratelimited("CLNP header has invalid version %d, should be %d\n", clnph->vers, CLNP_VERSION);
		goto discard_unsupported_vers;
	}

	/* check the checksum */
	if (clnph->cksum_lsb + clnph->cksum_msb != 0) {
		if (clnp_check_csum(skb) != 1) {
			pr_err_ratelimited("CLNP header checksum incorrect\n");
			err_location = 0;
			goto discard_bad_csum;
		}
	}

	/* check the lifetime (discard if the TTL is zero) */
	if (clnph->ttl == 0) {
		pr_err_ratelimited("TTL is 0\n");
		goto discard_syntax_error;
	}

	/* check the value range of the header */
	clnph_hdrlen = clnph->hdrlen;
	if (clnph_hdrlen < MIN_HDR_LEN || clnph_hdrlen > MAX_HDR_LEN) {
		pr_err_ratelimited("CLNP header size invalid: %d\n", clnph_hdrlen);
		goto discard_syntax_error;
	}

	/* check flag */
	int sp_flag = clnph->flag & SP_MASK;
	int ms_flag = clnph->flag & MS_MASK;
	int er_flag = clnph->flag & ER_MASK;
	int type_flag = clnph->flag & TYPE_MASK;

	/* check the PDU type flag */
	switch (type_flag) {
	case CLNP_DT:
	case CLNP_MD:
	case CLNP_ER:
	case CLNP_ERQ:
	case CLNP_ERP:
		break;
	default:
		goto discard_unknown_type;
	}

	/*
	 * Segmentation part
	 */
	if (sp_flag) {
		struct clnp_segment *seg = (struct clnp_segment*)clnph->next_part;

		/*
		 * Check whether the packet type is an Error Report PDU.
		 * If yes, it's an error because an Error Report PDU
		 * packet may not have any segmentation part.
		 */
		if (type_flag == CLNP_ER) {
			pr_err_ratelimited("an ER PDU may not have any segmentation part\n");
			goto discard_syntax_error;
		}

		pr_info("Analyzing the segmentation part:\n");

		/* print the value of the segmentation part */
		print_header_segment(seg);

		/* check the segmentation offset */
		pr_info("Check segmentation offset value: ");
		if (ntohs(seg->off) % 8 == 0) {
			pr_info("Segmentation offset is correct (multiple of 8)\n");
		} else {
			pr_err("Segmentation offset error (not multiple of 8)\n");
			goto discard_syntax_error;
		}
	}
	/* Else,
	 * if sp_flag is off but the packet has a segmentation part,
	 * the segmentation part is recognized as an option and will
	 * generate an error because the option code is unrecognized
	 *
	 * } -- erase this when done in opt_rcv (eus)
	 */

	clnp_rcv_finish(skb, clnph_derived, seg, fas_len, SP_derived, MS_derived
							, ER_derived, TYPE_derived);
	return 0;

discard_bad_csum:
	clnp_discard(skb, GEN_BADCSUM, err_location, GFP_KERNEL);
	return -GEN_BADCSUM;

discard_syntax_error:
	clnp_discard(skb, GEN_HDRSYNTAX, err_location, GFP_KERNEL);
	return -GEN_HDRSYNTAX;

discard_unknown_type:
	clnp_discard(skb, GEN_UNKNOWN, err_location, GFP_KERNEL);
	return -GEN_UNKNOWN;

discard_incomplete:
	clnp_discard(skb, GEN_INCOMPLETE, err_location, GFP_KERNEL);
	return -GEN_INCOMPLETE;

discard_unsupported_vers:
	clnp_discard(skb, DISC_UNSUPPVERS, err_location, GFP_KERNEL);
	return -DISC_UNSUPPVERS;
drop:
	kfree_skb(skb);
	return rc;
}

void clnp_rcv_finish(struct sk_buff *skb, struct clnphdr *clnph
			    , struct clnp_segment *seg, int fas_len, int sp_flag
				     , int ms_flag, int er_flag, int type_flag)
{
	__u8 our_addr[NSAP_ADDR_LEN] = {0}; /* address part's variable */

	struct clnphdr *clnph_skb = clnp_hdr(skb);

	/* options part's variables */
	int opt_idx = 0;
	int count = 0;

	/*
	 * Options part processing
	 */

	/*
	 * Check for the parameter of the options part. While the header length
	 * value is larger than (fixed + address + segmentation) length
	 * (fas_len), the CLNP header has an options part.
	 */
	if (clnph->hdrlen > fas_len) {
		struct clnp_options *opt;

		pr_info("Analyzing the parameter of the options part...\n");
		opt_idx = fas_len; /* starting index of the options part */
		while (opt_idx < clnph->hdrlen) {
			opt = (struct clnp_options *)(clnph_skb + opt_idx);

			/* print the value of the parameter */
			print_header_options(opt);

			if (opt->code == REASON_DISCARD) {
				if (type_flag == CLNP_ER) {
					pr_info("This is reason for discard\n");
				} else {
					pr_info("Error in reason for discard\n");
					goto discard_syntax_error;
				}

				/* fetch the next parameter */
				opt_idx += REASON_LEN;
			} else {
				if (opt_part_hndlr(opt) == -1)
					goto discard_syntax_error;

				count++; /* how many parts are there? */

				/* fetch the next parameter */
				opt_idx += (opt->len + 2);
			}
		}
		pr_info("Found %d parameter(s) in the options part\n", count);
	} else {
		pr_info("No parameter exists in the options part\n");
	}

	/*
	 *  Address part processing
	 */
	get_nsap_addr(our_addr);

	/* check the address length value */
	pr_info("Checking the addresses' length... ");
	if (clnp_addr_ck(clnph) == 1) {
		pr_info("No error in address length (value = 20)\n");
	} else {
		pr_info("Error address length (value != 20)\n");
		goto discard_syntax_error;
	}

	if (is_our_dgram(clnph, our_addr) == 1) {
		pr_info("Status: The packet is ours\n");
		clnp_local_deliver(skb, clnph, seg, ms_flag);
		return;
	}

	pr_info("Status: The packet is not ours\n");
	pr_info("Call the forwarding function\n");

	return;

discard_syntax_error:
	clnp_discard(skb, GEN_HDRSYNTAX, 0, GFP_KERNEL);
}

int is_our_dgram(struct clnphdr *clnph, __u8 *my_addr)
{
	if (clnph->dest_len == NSAP_ADDR_LEN &&
		(memcmp(my_addr, clnph->dest_addr, clnph->dest_len) == 0)) {
		return 1;
	} else {
		return 0;
	}
}

void clnp_local_deliver(struct sk_buff *skb, struct clnphdr *clnph,
					  struct clnp_segment *seg, int ms_flag)
{
	if (seg && (ms_flag || ntohs(seg->off) != 0)) {
		pr_info("Defragmenting packet...\n");
		//skb = clnp_defrag(skb, clnph->dest_addr, clnph->src_addr, seg);
		skb = clnp_defrag(skb);
		if (!skb)
			return;
	}
	clnp_local_deliver_finish(skb);
}

void clnp_local_deliver_finish(struct sk_buff *skb)
{
	skb_pull(skb, clnp_hdr(skb)->hdrlen);
	pr_info("Packet is now passed to the transport layer\n");
}
