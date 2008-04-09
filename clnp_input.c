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
 *		Tadeus:		2008/03/30:
 *				Change the switch block in optional part
 *				processing of clnp_rcv_finish() to a private
 *				function opt_part_hndlr()
 *				Changing the use of a kmalloc() dynamically
 *				allocated temporary variable `opt', which is
 *				used to hold an optional part during optional
 *				part processing of clnp_rcv_finish(), to an
 *				ordinary variable within the right scope to
 *				avoid overhead associated with kmalloc().
 *				Change the bulk of else part in function
 *				clnp_decompose() with a single function memset()
 *				because the bulk of else part only sets clnph
 *				to zero
 *				2008/04/06:
 *				Replace all invocation of masking() with
 *				(& CNF_*)
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/clnp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/clnp.h>

/*
 * Begin: Private function prototypes
 */

/**
 * opt_part_hndlr - a private function to be used within clnp_rcv_finish()
 * @opt: the optional part to be processed
 *
 * Returns -1 if opt->cno_code is illegal (i.e., not listed in linux/clnp.h).
 * Returns 0 if opt->cno_code is legal.
 */
static int opt_part_hndlr(struct clnp_options *opt)
						__attribute__ ((always_inline));

/*
 * End: Private function prototypes
 */

static int opt_part_hndlr(struct clnp_options *opt)
{
	switch (opt->cno_code) {
	case CLNPOPT_PC_PAD:
		printk(KERN_INFO "Option: padding\n");
		break;
	case CLNPOPT_PC_SEC:
		printk(KERN_INFO "Option: security\n");
		break;
	case CLNPOPT_PC_SRCROUTE:
		printk(KERN_INFO "Option: source routeing\n");
		break;
	case CLNPOPT_PC_ROR:
		printk(KERN_INFO "Option: recording of route\n");
		break;
	case CLNPOPT_PC_QOS:
		printk(KERN_INFO "Option: quality of service maintenance\n");
		break;
	case CLNPOPT_PC_PRIOR:
		printk(KERN_INFO "Option: priority\n");
		break;
	case CLNPOPT_PC_PBSC:
		printk(KERN_INFO "Option: prefix based scope control\n");
		break;
	case CLNPOPT_PC_RSC:
		printk(KERN_INFO "Option: radius scope control\n");
		break;
	default:
		printk(KERN_INFO "Option: unknown option\n");
		return -1;
	}

	return 0;
}

int clnp_addr_ck (struct clnphdr * clnph)
{
	return (clnph->dest_len == 20 && clnph->src_len == 20);
}

int clnp_rcv(struct sk_buff *skb, struct net_device *dev,
			    struct packet_type *pt, struct net_device *orig_dev)
{
	/* pointer to fixed and address part */
	struct clnphdr *clnph = NULL;

	/* fixed part variables */
	int	sp_flag;	/* hold the SP flag value */
	int	ms_flag;	/* hold the MS flag value */
	int	er_flag;	/* hold the ER flag value */
	int	type_flag;	/* hold the PDU type value */

	/* segmentation part variables */
	struct clnp_segment *seg = NULL; /* pointer to segmentation part */
	__u8	*seg_temp = NULL; /* temporary pointer to a segmented part */

	/* optional part variables */
	int	fas_len; /* length of fixed + address + segment part */

	printk(KERN_INFO "clnp_rcv(): Hello, a CLNP packet is captured.\n");

	/*
	 * Reads the skb->nh.raw we've just accepted and saves the values in
	 * the clnphdr struct
	 */
	clnph = (struct clnphdr *) kmalloc(sizeof(__u8) * MIN_HDR_LEN
								  , GFP_KERNEL);
	if (clnph) {
		printk(KERN_INFO "Processing header decomposition...\n");
		clnp_decompose(skb, clnph); /* this assigns values to clnph */
	} else {
		printk(KERN_INFO "Cannot allocate memory for clnph\n");
	}

	print_header_clnp(clnph); /* print the header (fixed & address part) */

	/*
	 * The following is the header format analysis functions
	 */

	/*
	 * Fixed part
	 */
	printk(KERN_INFO "Performing header format analysis...\n");

	if (clnph->cnf_proto_id == NLPID) {
		/* check the checksum */
		printk(KERN_INFO "Checking checksum value...\n");
		if (clnph->cnf_cksum_lsb + clnph->cnf_cksum_msb != 0) {
			if (clnp_check_csum(skb, (int) clnph->cnf_hdr_len) == 1)
			{
				printk(KERN_INFO "Checksum is correct\n");
			} else {
				printk(KERN_INFO "Checksum error\n");
				goto discard_bad_csum;
			}
		} else {
			printk(KERN_INFO "Checksum is correct\n");
		}

		/* check length indicator */
		printk(KERN_INFO "Checking header length value...\n");
		printk(KERN_INFO "Header length: %d\n", clnph->cnf_hdr_len);
		if (clnph->cnf_hdr_len < MIN_HDR_LEN
					  || clnph->cnf_hdr_len > MAX_HDR_LEN) {
			printk(KERN_INFO "Header length error\n");
			goto discard_syntax_error;
		} else {
			printk(KERN_INFO "Header length is OK\n");
		}

		/* check the version */
		printk(KERN_INFO "Checking version value...\n");
		if (clnph->cnf_vers != CLNPVERSION) {
			printk(KERN_INFO "Version error\n");
			goto discard_syntax_error;
		} else {
			printk(KERN_INFO "Version is OK\n");
		}

		/* check the lifetime (discard if the TTL is zero) */
		printk(KERN_INFO "Checking lifetime value...\n");
		if (clnph->cnf_ttl == 0) {
			printk(KERN_INFO "TTL expired\n");
			goto discard_syntax_error;
		} else {
			printk(KERN_INFO "TTL is OK\n");
		}

		/* check the flag - SP, MS, and E/R */
		printk(KERN_INFO "Checking flag status...\n");
		sp_flag = clnph->cnf_flag & CNF_SP;
		printk(KERN_INFO "sp = %d\n", sp_flag);
		ms_flag = clnph->cnf_flag & CNF_MS;
		printk(KERN_INFO "ms = %d\n", ms_flag);
		er_flag = clnph->cnf_flag & CNF_ER;
		printk(KERN_INFO "er = %d\n", er_flag);

		/* check the PDU type flag */
		type_flag = clnph->cnf_flag & CNF_TYPE;
		if ((type_flag != CLNP_DT) && (type_flag != CLNP_MD)
			    && (type_flag != CLNP_ER) && (type_flag != CLNP_ERQ)
			    			   && (type_flag != CLNP_ERP)) {
			printk(KERN_INFO "Invalid PDU type\n");
			goto discard_unknown_type;
		}

		/* check the segment length */
		if (!sp_flag) {
			printk(KERN_INFO "Total CLNP packet length: %d\n"
							   , clnph->cnf_seglen);
		}

		/*
		 * Segmentation part
		 */
		if (sp_flag) {
			/*
			 * Check whether the packet type is an Error Report PDU.
			 * If yes, it's an error because an Error Report PDU
			 * packet may not have any segmentation part.
			 */
			if (type_flag == CLNP_ER) {
				printk(KERN_INFO "Error: an ER PDU may not have"
						    " any segmentation part\n");
				goto discard_syntax_error;
			}

			/*
			 * If there's a segmentation part, add 6 octets
			 * to indicate the total header length
			 */
			fas_len = FA_LEN + SEG_LEN;

			seg = (struct clnp_segment *) kmalloc(
				       sizeof(struct clnp_segment), GFP_KERNEL);
			printk(KERN_INFO "Analyzing the segmentation part...\n")
									       ;
			if (seg) {
#if defined(__BIG_ENDIAN_BITFIELD)
				seg_temp = (__u8*) &seg->cng_id;
				seg_temp[0] = skb->nh.raw[51];
				seg_temp[1] = skb->nh.raw[52];

				seg_temp = (__u8*) &seg->cng_off;
				seg_temp[0] = skb->nh.raw[53];
				seg_temp[1] = skb->nh.raw[54];

				seg_temp = (__u8*) &seg->cng_tot_len;
				seg_temp[0] = skb->nh.raw[55];
				seg_temp[1] = skb->nh.raw[56];
#elif defined(__LITTLE_ENDIAN_BITFIELD)
				seg_temp = (__u8*) &seg->cng_id;
				seg_temp[0] = skb->nh.raw[52];
				seg_temp[1] = skb->nh.raw[51];

				seg_temp = (__u8*) &seg->cng_off;
				seg_temp[0] = skb->nh.raw[54];
				seg_temp[1] = skb->nh.raw[53];

				seg_temp = (__u8*) &seg->cng_tot_len;
				seg_temp[0] = skb->nh.raw[56];
				seg_temp[1] = skb->nh.raw[55];
#else
#error Only handle little and big endian byte-orders
#endif

				/* print the value of the segmentation part */
				print_header_segment(seg);

				/* check the segmentation offset */
				printk(KERN_INFO "Checking segmentation offset"
							      " value. . . \n");
				if (seg->cng_off % 8 == 0) {
					printk(KERN_INFO "Segmentation offset"
					       " is correct (multiple of 8)\n");
				} else {
					printk(KERN_INFO "Segmentation offset"
						" error (not multiple of 8)\n");
					goto discard_syntax_error;
				}
			} else {
				printk(KERN_INFO "Cannot allocate memory for"
						       " segmentation part!\n");
			}
		} else {
			printk(KERN_INFO "No segmentation part exists\n");

			/*
			 * If there's no segment part exist, the total header
			 * length is fixed + address only
			 */
			fas_len = FA_LEN;
		}

		clnp_rcv_finish(skb, clnph, seg, fas_len, sp_flag, ms_flag
							  , er_flag, type_flag);
		return 0;
	} else if (clnph->cnf_proto_id == 0) {
		printk(KERN_INFO "Inactive network layer protocol\n");
		goto discard_syntax_error;
	} else {
		printk(KERN_INFO "Unknown network layer protocol\n");
		goto discard_syntax_error;
	}

discard_bad_csum:
	free_mem_alloc(clnph, seg);
	clnp_discard(skb, GEN_BADCSUM);
	return -1;

discard_syntax_error:
	free_mem_alloc(clnph, seg);
	clnp_discard(skb, GEN_HDRSYNTAX);
	return -2;

discard_unknown_type:
	free_mem_alloc(clnph, seg);
	clnp_discard(skb, GEN_UNKNOWN);
	return -3;
}

void clnp_rcv_finish(struct sk_buff *skb, struct clnphdr *clnph,
			     struct clnp_segment *seg, int fas_len, int sp_flag,
					int ms_flag, int er_flag, int type_flag)
{
	/* address part's variable */
	__u8 our_addr[CLNP_ADDR_LEN] = {0};

	/* optional parts' variables */
	int opt_idx = 0;
	int count = 0;

	/*
	 * Optional part processing
	 */

	/*
	 * Check for optional parts. While the header length value is larger than
	 * (fixed + address + segment) length (fas_len), there is an optional
	 * part after it.
	 */
	if (clnph->cnf_hdr_len > fas_len) {
		struct clnp_options opt;

		printk(KERN_INFO "Analyzing the optional part...\n");
		opt_idx = fas_len; /* starting index of the optional part */
		while (opt_idx < clnph->cnf_hdr_len) {
			opt.cno_code = skb->nh.raw[opt_idx];
			opt.cno_len = skb->nh.raw[opt_idx + 1];
			opt.cno_value = &skb->nh.raw[opt_idx + 2];

			/* print the value of the optional part */
			print_header_options(&opt);

			if (opt.cno_code != REASON_DISCARD) {
				if (opt_part_hndlr(&opt) == -1)
				{
					goto discard_syntax_error;
				}
				count++; /* how many parts are there? */

				/* fetch the next optional part */
				opt_idx += (opt.cno_len + 2);
			} else {
				if (type_flag == CLNP_ER) {
					printk(KERN_INFO "This is reason for"
								  " discard\n");
				} else {
					printk(KERN_INFO "Error in reason for"
								  " discard\n");
					goto discard_syntax_error;
				}

				/* fetch the next optional part */
				opt_idx += REASON_LEN;
			}
		}
		printk(KERN_INFO "Found %d optional parts\n", count);
	} else {
		printk(KERN_INFO "No optional part exists\n");
	}

	/*
	 *  Address part processing
	 */
	get_nsap_addr(our_addr);

	/* check the address length value */
	printk(KERN_INFO "Checking the addresses' length. . . ");
	if (clnp_addr_ck(clnph) == 1) {
		printk(KERN_INFO "No error in address length (value = 20)\n");
	} else {
		printk(KERN_INFO "Error address length (value != 20)\n");
		goto discard_syntax_error;
	}

	if (is_our_dgram(clnph, our_addr) == 1) {
		printk(KERN_INFO "Status: The packet is ours\n");
		clnp_local_deliver(skb, clnph, seg, ms_flag);
		return;
	} else {
		printk(KERN_INFO "Status: The packet is not ours\n");
		printk(KERN_INFO "Call the forwarding function\n");
		return;
	}

discard_syntax_error:
	free_mem_alloc(clnph, seg);
	clnp_discard(skb, GEN_HDRSYNTAX);
}

int is_our_dgram(struct clnphdr *clnph, __u8 *my_addr)
{
	if (clnph->dest_len == CLNP_ADDR_LEN
		 && (memcmp(my_addr, clnph->dest_addr, clnph->dest_len) == 0)) {
		return 1;
	} else {
		return 0;
	}
}

void clnp_local_deliver(struct sk_buff *skb, struct clnphdr *clnph,
					  struct clnp_segment *seg, int ms_flag)
{
	if (seg) {
		if (ms_flag || seg->cng_off != 0) {
			printk(KERN_INFO "Defragmenting packet...\n");
			skb = (struct sk_buff *) clnp_defrag(skb
							, clnph->dest_addr
							, clnph->src_addr, seg);
			if (!skb) {
				return;
			}
		}
	}
	clnp_local_deliver_finish(skb);

	free_mem_alloc(clnph, seg); /* free clnph and seg if they exist */
}

void clnp_local_deliver_finish(struct sk_buff *skb)
{
	unsigned int clnp_hdr_len = skb->nh.raw[IDX_HDR_LEN];

	printk(KERN_INFO "The complete skb is delivered to the transport"
								    " layer\n");

	__skb_pull(skb, clnp_hdr_len);

	/* point into the CLNP datagram, just past the header. */
	skb->h.raw = skb->data;

	printk(KERN_INFO "Packet is now passed to the transport layer\n");
}

int free_mem_alloc(struct clnphdr *clnph, struct clnp_segment *seg)
{
	if (clnph != NULL) {
		kfree(clnph);
		printk(KERN_INFO "clnph free\n");
	}

	if (seg != NULL) {
		kfree(seg);
		printk(KERN_INFO "seg free\n");
	}

	return 0;
}
