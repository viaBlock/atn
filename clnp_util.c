// SPDX-License-Identifier: GPL-2.0
/*
 * clnp_util.c	Functions that are used together inside CLNP module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	- 2007/08/21:
 *				* Declare utility functions for CLNP packet
 *				processing
 *		Husni Fahmi:	- 2007/08/28:
 *				* Finished debugging clnp_decompose() and
 *				print_header_clnp()
 *		Tadeus:		- 2008/04/06:
 *				* Remove masking() because it causes too much
 *				overhead (the programmer should have used the
 *				bitwise operator `&' as well as `if (flag)' or
 *				`if (!flag)' to test whether or not the flag is
 *				set)
 *				* Remove power() because it is unused
 *				* Optimize set_flag()
 *				* Revise print_data_hex() to produce a neat
 *				output
 *				- 2008/04/13:
 *				* Add clnp_hdr() and replace all instances of
 *				`nh' that is used to get the CLNP header part
 *				so that it is more maintainable when the CLNP
 *				header is pointed by `h' instead of `nh' as
 *				a result of LLC header processing
 *				- 2008/04/14:
 *				* Replace clnph->seglen with
 *				ntohs(clnph->seglen) because a corresponding
 *				modification in include/linux/clnp.h states that
 *				clnph->seglen is in network byte order
 *				* Remove clnp_decompose(skb, clnph) and
 *				free_mem_alloc() for a reason stated in
 *				clnp_input.c
 *				* Remove merge_chars_to_short() because its sole
 *				use equals to ntohs(clnph->seglen)
 *				* Replace the following construct
 *				#if defined(__BIG_ENDIAN_BITFIELD)
 *				...
 *				#elif defined(__LITTLE_ENDIAN_BITFIELD)
 *				...
 *				#else
 *				...
 *				#endif
 *				with the equivalent ntohs()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version 2
 *		of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <net/clnp.h>

void print_header_clnp(struct clnphdr *clnph)
{
	int i = 0;

	pr_info("Printing CLNP header:\n");
	pr_info("Network Layer Protocol ID: 0x%02X\n", clnph->nlpid);
	pr_info("Header length: %d\n", clnph->hdrlen);
	pr_info("Version: %d\n", clnph->vers);
	pr_info("Time-to-live: %d\n", clnph->ttl);
	pr_info("Flags: SP: %d MS: %d ER: %d PDU type:",
		!!(clnph->flag & SP_MASK), !!(clnph->flag & MS_MASK), !!(clnph->flag & ER_MASK));

	switch (clnph->flag & TYPE_MASK) {
	case CLNP_DT:
		pr_info("DT PDU (normal data)\n");
		break;
	case CLNP_MD:
		pr_info("MD PDU (multicast data)\n");
		break;
	case CLNP_ER:
		pr_info("ER PDU (error report)\n");
		break;
	case CLNP_ERQ:
		pr_info("ERQ PDU (echo request)\n");
		break;
	case CLNP_ERP:
		pr_info("ERP PDU (echo reply)\n");
		break;
	default:
		pr_info("unknown\n");
	}
	pr_info("Segmentation length: %d\n", ntohs(clnph->seglen));
	pr_info("Checksum MSB: %d\n", clnph->cksum_msb);
	pr_info("Checksum LSB: %d\n", clnph->cksum_lsb);
	pr_info("Destination address length: %d\n", clnph->dest_len);
	pr_info("Destination address: 0x");
	for (i = 0; i < clnph->dest_len; i++)
		pr_info("%02X%s", clnph->dest_addr[i], (i + 1 == clnph->dest_len) ? "\n" : " ");
	pr_info("Source address length: %d\n", clnph->src_len);
	pr_info("Source address: 0x");
	for (i = 0; i < clnph->src_len; i++)
		pr_info("%02X%s", clnph->src_addr[i], (i + 1 == clnph->src_len) ? "\n" : " ");
}

void print_header_segment(struct clnp_segment *seg)
{
	pr_info("Printing CLNP segmentation part:\n");
	pr_info("Data unit ID: %d\n", ntohs(seg->id));
	pr_info("Segment offset: %d\n", ntohs(seg->off));
	pr_info("Total length: %d\n", ntohs(seg->tot_len));
}

void print_header_options(struct clnp_options *opt)
{
	int i = 0;

	pr_info("Printing an optional part of a CLNP header\n");
	pr_info("Option parameter code: 0x%02X -> ", opt->code);
	switch (opt->code) {
	case CLNPOPT_PC_PAD:
		pr_info("padding\n");
		break;
	case CLNPOPT_PC_SEC:
		pr_info("security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		pr_info("source routing\n");
		break;
	case CLNPOPT_PC_ROR:
		pr_info("recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		pr_info("quality of service\n");
		break;
	case CLNPOPT_PC_PRIOR:
		pr_info("priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		pr_info("prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		pr_info("radius scope control\n");
		break;
	default:
		pr_info("unknown\n");
	}
	pr_info("Option parameter length: %d\n", opt->len);
	for (i = 0; i < opt->len; i++)
		pr_info("Option parameter value[%d]: 0x%02X\n", i, opt->value[i]);
}

void print_data_hex(struct sk_buff *skb)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	const int len = ntohs(clnph->seglen);

	pr_info("Printing payload:\n");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 16, clnph + 1, len, 1);
}
