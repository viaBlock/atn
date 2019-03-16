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

#define print_func   pr_err

void print_header_clnp(struct clnphdr *clnph)
{
	print_func("Printing CLNP header:\n");
	print_func("Network Layer Protocol ID: 0x%02X\n", clnph->nlpid);
	print_func("Header length: %d\n", clnph->hdrlen);
	print_func("Version: %d\n", clnph->vers);
	print_func("Time-to-live: %d\n", clnph->ttl);
	print_func("Flags: SP: %d MS: %d ER: %d PDU type:",
		!!(clnph->flag & SP_MASK), !!(clnph->flag & MS_MASK), !!(clnph->flag & ER_MASK));

	switch (clnph->flag & TYPE_MASK) {
	case CLNP_DT:
		print_func("DT PDU (normal data)\n");
		break;
	case CLNP_MD:
		print_func("MD PDU (multicast data)\n");
		break;
	case CLNP_ER:
		print_func("ER PDU (error report)\n");
		break;
	case CLNP_ERQ:
		print_func("ERQ PDU (echo request)\n");
		break;
	case CLNP_ERP:
		print_func("ERP PDU (echo reply)\n");
		break;
	default:
		print_func("unknown\n");
	}
	print_func("Segmentation length: %d\n", ntohs(clnph->seglen));
	print_func("Checksum MSB: %d\n", clnph->cksum_msb);
	print_func("Checksum LSB: %d\n", clnph->cksum_lsb);
	print_func("Destination address length: %d\n", clnph->dest_len);
	print_hex_dump(KERN_ERR, "Destination address:", DUMP_PREFIX_NONE, 32, 1,
			clnph->dest_addr, clnph->dest_len, true);

	print_func("Source address length: %d\n", clnph->src_len);
	print_hex_dump(KERN_ERR, "Source address:", DUMP_PREFIX_NONE, 32, 1,
			clnph->src_addr, clnph->src_len, true);
}

void print_header_segment(struct clnp_segment *seg)
{
	print_func("Printing CLNP segmentation part:\n");
	print_func("Data unit ID: %d\n", ntohs(seg->id));
	print_func("Segment offset: %d\n", ntohs(seg->off));
	print_func("Total length: %d\n", ntohs(seg->tot_len));
}

void print_header_options(struct clnp_options *opt)
{
	print_func("Printing an optional part of a CLNP header\n");
	print_func("Option parameter code: 0x%02X -> ", opt->code);
	switch (opt->code) {
	case CLNPOPT_PC_PAD:
		print_func("padding\n");
		break;
	case CLNPOPT_PC_SEC:
		print_func("security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		print_func("source routing\n");
		break;
	case CLNPOPT_PC_ROR:
		print_func("recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		print_func("quality of service\n");
		break;
	case CLNPOPT_PC_PRIOR:
		print_func("priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		print_func("prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		print_func("radius scope control\n");
		break;
	default:
		print_func("unknown\n");
	}
	print_func("Option parameter length: %d\n", opt->len);
	print_hex_dump(KERN_ERR, "Option parameter:", DUMP_PREFIX_OFFSET, 16, 1,
			opt->value, opt->len, true);
}

void print_data_hex(struct sk_buff *skb)
{
	struct clnphdr *clnph = clnp_hdr(skb);
	const int len = ntohs(clnph->seglen);

	print_hex_dump(KERN_ERR, "PAYLOAD:", DUMP_PREFIX_OFFSET, 16, 1, clnph + 1, len, 1);
}

void print_simple(const u8 *buf, const int len)
{
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 1, buf, len, 1);
}