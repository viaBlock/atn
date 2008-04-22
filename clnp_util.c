/*
 * clnp_util.c	Functions that are used together inside CLNP module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	2007/08/21:
 *				Declare utility functions for CLNP packet
 *				processing
 *		Husni Fahmi:	2007/08/28:
 *				Finished debugging clnp_decompose() and
 *				print_header_clnp()
 *		Tadeus:		2008/04/06:
 *				Remove masking() because it causes too much
 *				overhead (the programmer should have used the
 *				bitwise operator `&' as well as `if (flag)' or
 *				`if (!flag)' to test whether or not the flag is
 *				set)
 *				Remove power() because it is unused
 *				Optimize set_flag()
 *				Revise print_data_hex() to produce a neat output
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <net/clnp.h>

void clnp_decompose(struct sk_buff *skb, struct clnphdr *clnph)
{
	/* temporary pointer to the segment length value */
	__u8 *segment_len = (__u8*) &clnph->cnf_seglen;

	if (skb->nh.raw[IDX_PROTO_ID] != 0) {
#if defined(__BIG_ENDIAN_BITFIELD)
		segment_len[0] = skb->nh.raw[IDX_SEGLEN_MSB];
		segment_len[1] = skb->nh.raw[IDX_SEGLEN_LSB];
#elif defined(__LITTLE_ENDIAN_BITFIELD)
		segment_len[0] = skb->nh.raw[IDX_SEGLEN_LSB];
		segment_len[1] = skb->nh.raw[IDX_SEGLEN_MSB];
#else
#error Only handle little and big endian byte-orders
#endif

		/* get the value of network protocol ID */
		clnph->cnf_proto_id = skb->nh.raw[IDX_PROTO_ID];

		/* get the value of header length */
		clnph->cnf_hdr_len = skb->nh.raw[IDX_HDR_LEN];

		/* get the value of version */
		clnph->cnf_vers = skb->nh.raw[IDX_VERS];

		/* get the value of lifetime */
		clnph->cnf_ttl = skb->nh.raw[IDX_TTL];

		/* get the value of flags: SP, MS, ER, and PDU type */
		clnph->cnf_flag = skb->nh.raw[IDX_FLAG];

		/* get the value of checksum - most significant byte */
		clnph->cnf_cksum_msb = skb->nh.raw[IDX_CKSUM_MSB];

		/* get the value of checksum - least significant byte */
		clnph->cnf_cksum_lsb = skb->nh.raw[IDX_CKSUM_LSB];

		/* get the value of the destination address length */
		clnph->dest_len = skb->nh.raw[IDX_DEST_LEN];

		/* get the copy the destination address */
		memcpy(clnph->dest_addr, &skb->nh.raw[IDX_DEST_ADDR]
							       , CLNP_ADDR_LEN);

		/* get the value of the source address length */
		clnph->src_len = skb->nh.raw[IDX_SRC_LEN];

		/* get the copy the source address */
		memcpy(clnph->src_addr, &skb->nh.raw[IDX_SRC_ADDR]
							       , CLNP_ADDR_LEN);
	} else {
		memset(clnph, 0, MIN_HDR_LEN);
	}
}

unsigned short merge_chars_to_short(__u8 idx_msb, __u8 idx_lsb)
{
	unsigned short len = 0;
	__u8 *lenptr = (unsigned char *) &len;

#if defined(__LITTLE_ENDIAN_BITFIELD)
	lenptr[0] = idx_lsb;
	lenptr[1] = idx_msb;
#elif defined(__BIG_ENDIAN_BITFIELD)
	lenptr[0] = idx_msb;
	lenptr[1] = idx_lsb;
#error Only handle little and big endian byte-orders
#endif

	return len;
}

void print_header_clnp(struct clnphdr *clnph)
{
	int i = 0;

	printk(KERN_INFO "Printing CLNP header:\n");
	printk(KERN_INFO "Network Layer Protocol ID: 0x%02X\n"
							 , clnph->cnf_proto_id);
	printk(KERN_INFO "Header length: %d\n", clnph->cnf_hdr_len);
	printk(KERN_INFO "Version: %d\n", clnph->cnf_vers);
	printk(KERN_INFO "Time-to-live: %d\n", clnph->cnf_ttl);
	printk(KERN_INFO "Flags: SP: %d MS: %d ER: %d PDU type:"
			    , clnph->cnf_flag & CNF_SP, clnph->cnf_flag & CNF_MS
		 				    , clnph->cnf_flag & CNF_ER);
	switch (clnph->cnf_flag & CNF_TYPE) {
	case CLNP_DT:
		printk(KERN_INFO "DT PDU (normal data)\n");
		break;
	case CLNP_MD:
		printk(KERN_INFO "MD PDU (multicast data)\n");
		break;
	case CLNP_ER:
		printk(KERN_INFO "ER PDU (error report)\n");
		break;
	case CLNP_ERQ:
		printk(KERN_INFO "ERQ PDU (echo request)\n");
		break;
	case CLNP_ERP:
		printk(KERN_INFO "ERP PDU (echo reply)\n");
		break;
	default:
		printk(KERN_INFO "unknown\n");
	}
	printk(KERN_INFO "Segmentation length: %d\n", clnph->cnf_seglen);
	printk(KERN_INFO "Checksum MSB: %d\n", clnph->cnf_cksum_msb);
	printk(KERN_INFO "Checksum LSB: %d\n", clnph->cnf_cksum_lsb);
	printk(KERN_INFO "Destination address length: %d\n", clnph->dest_len);
	printk(KERN_INFO "Destination address: 0x");
	for (i = 0; i < clnph->dest_len; i++) {
		printk(KERN_INFO "%02X%s", clnph->dest_addr[i]
				     , (i + 1 == clnph->dest_len) ? "\n" : " ");
	}
	printk(KERN_INFO "Source address length: %d\n", clnph->src_len);
	printk(KERN_INFO "Source address: 0x");
	for (i = 0; i < clnph->src_len; i++) {
		printk(KERN_INFO "%02X%s", clnph->src_addr[i]
				      , (i + 1 == clnph->src_len) ? "\n" : " ");
	}
}

void print_header_segment(struct clnp_segment *seg)
{
	printk(KERN_INFO "Printing CLNP segmentation part:\n");
	printk(KERN_INFO "Data unit ID: %d\n", seg->cng_id);
	printk(KERN_INFO "Segment offset: %d\n", seg->cng_off);
	printk(KERN_INFO "Total length: %d\n", seg->cng_tot_len);
}

void print_header_options(struct clnp_options *opt)
{
	int i = 0;

	printk(KERN_INFO "Printing an optional part of a CLNP header\n");
	printk(KERN_INFO "Option parameter code: 0x%02X -> ", opt->cno_code);
	switch (opt->cno_code) {
	case CLNPOPT_PC_PAD:
		printk(KERN_INFO "padding\n");
		break;
	case CLNPOPT_PC_SEC:
		printk(KERN_INFO "security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		printk(KERN_INFO "source routing\n");
		break;
	case CLNPOPT_PC_ROR:
		printk(KERN_INFO "recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		printk(KERN_INFO "quality of service\n");
		break;
	case CLNPOPT_PC_PRIOR:
		printk(KERN_INFO "priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		printk(KERN_INFO "prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		printk(KERN_INFO "radius scope control\n");
		break;
	default:
		printk(KERN_INFO "unknown\n");
	}
	printk(KERN_INFO "Option parameter length: %d\n", opt->cno_len);
	for(i = 0; i < opt->cno_len; i++) {
		printk(KERN_INFO "Option parameter value[%d]: 0x%02X\n", i
							   , opt->cno_value[i]);
	}
}

void print_data_hex(struct sk_buff *skb)
{
	unsigned short len = merge_chars_to_short(skb->nh.raw[IDX_SEGLEN_MSB]
						 , skb->nh.raw[IDX_SEGLEN_LSB]);
	unsigned short hdrlen = (unsigned short) skb->nh.clnph->cnf_hdr_len;
	unsigned short i = 0;
	unsigned short j = 0;

	printk(KERN_INFO "Printing payload:\n");
	for (i = hdrlen; i < len; i += 16) {
		for (j = 0; j < 16 && i + j < len; j++) {
			printk(KERN_INFO "%02X%s", skb->nh.raw[i + j]
							, (j != 15) ? " " : "");
		}
		while (j < 16) {
			printk(KERN_INFO "  %s", (j != 15) ? " " : "");
			++j;
		}
		printk(KERN_INFO ": ");
		for (j = 0; j < 16 && i + j < len; j++) {
			if (isprint (skb->nh.raw[i + j])) {
				printk(KERN_INFO "%c", skb->nh.raw[i + j]);
			} else {
				printk(KERN_INFO ".");
			}
		}
		printk(KERN_INFO "\n");
	}
}
