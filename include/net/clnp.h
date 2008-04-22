/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	2007/08/21:
 *				Declare utility functions for CLNP packet
 *				processing
 *		Tadeus:		2008/03/30:
 *				Bringing all function prototypes to this file
 *				except those declared static
 *				Putting all function documentations in
 *				kernel-doc style (kernel-doc nano-HOWTO)
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_CLNP_H
#define _NET_CLNP_H

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/skbuff.h>

/*
 * Functions provided by af_atn.c
 */

/**
 * get_nsap_addr - returns the NSAP address of this host in addr
 * @addr: an array of size CLNP_ADDR_LEN to hold this host's NSAP address
 */
void get_nsap_addr(__u8 *addr) __attribute__ ((nonnull));

/*
 * Functions provided by clnp_input.c
 */

/**
 * clnp_local_deliver_finish - sets skb->data to point to the transport header
 *
 * The pointer of skb->h.raw points to the skb->data
 */
extern void clnp_local_deliver_finish(struct sk_buff *skb);

/**
 * clnp_local_deliver
 *
 * Reassemblies the segmented PDUs if needed and then they are passed to the
 * transport layer. The reassembly function is called only if it is needed.
 */
extern void clnp_local_deliver(struct sk_buff *skb, struct clnphdr *clnph
				       , struct clnp_segment *seg, int ms_flag);

/**
 * clnp_rcv_finish - analyzes the optional parts
 *
 * Print error messages and call clnp_discard function if there is any error
 * detected. Analyze whether to call local delivery or source routing function.
 */
extern void clnp_rcv_finish(struct sk_buff *skb, struct clnphdr *clnph
			    , struct clnp_segment *seg, int fas_len, int sp_flag
				     , int ms_flag, int er_flag, int type_flag);


/**
 * clnp_rcv - decomposes the received skb and analyzes the network header part
 *
 * Print error messages and call clnp_discard function if there is any error
 * detected.
 * Return 0 if everything is okay.
 * Return -1 in case of checksum error.
 * Return -2 in case the header does not follow the standard.
 * Return -3 in case of invalid PDU type.
 */
extern int clnp_rcv(struct sk_buff *skb, struct net_device *dev
			 , struct packet_type *pt, struct net_device *orig_dev);

/**
 * free_mem_alloc - frees the memory allocation when a packet is discarded
 *
 * Both clnph and seg are freed.
 */
extern int free_mem_alloc(struct clnphdr *clnph, struct clnp_segment *seg);

/**
 * is_our_dgram - checks if the received packet's dest addr is the same as ours
 *
 * Return 1 if the address is the same (i.e., the packet is for us).
 * Return 0 if the address is different (i.e., the packet is not for us).
 */
extern int is_our_dgram(struct clnphdr *clnph, __u8 *my_addr);

/**
 * clnp_addr_ck - checks the lengths of the destination and source addresses
 *
 * Return 1 if each of the lengths is exactly 20.
 * Return 0 if not all of the lengths is exactly 20.
 */
extern int clnp_addr_ck (struct clnphdr *clnph);

/*
 * Functions provided by clnp_csum.c
 */

/**
 * clnp_gen_csum - generates checksum of CLNP header
 *
 * Put the 2 bytes checksum values into the skb packet
 * (offset 7 and 8 OR octet 8 and 9 of skb->nh.raw).
 */
extern void clnp_gen_csum(struct sk_buff *skb, int hdrlen);

/**
 * clnp_check_csum - performs error detection on CLNP header
 *
 * Return 0 if checksum calculation failed (error detected).
 * Return 1 if checksum calculation succeed (no error detected).
 */
extern int clnp_check_csum(struct sk_buff *skb, int hdrlen);

/**
 * clnp_adjust_csum - adjusts the checksum parameter when an octet is altered
 * @idx_changed: the index of the value in skb to be changed from old to new
 *
 * This is useful when the value of TTL field must be changed.
 * skb will be dropped if it contains checksum error.
 */
extern void clnp_adjust_csum(struct sk_buff *skb, int idx_changed
					      , __u8 new_value, __u8 old_value);

/*
 * Functions provided by clnp_err.c
 */

/**
 * clnp_emit_er
 */
extern void clnp_emit_er(struct sk_buff *skb, __u8 reason);

/**
 * clnp_discard
 *
 * Discards an error PDU and emit error report PDU if E/R flag is set.
 */
extern void clnp_discard(struct sk_buff *skb, __u8 reason);

/*
 * Functions provided by clnp_fragment.c
 */

/**
 * clnp_defrag - the main function for reassembly
 *
 * This is the function that must be called when you want to do reassembly.
 */
extern struct sk_buff *clnp_defrag(struct sk_buff *skb, __u8 *dest, __u8 *src
						    , struct clnp_segment *seg);

/**
 * clnp_find
 *
 * Find the corresponding fargment list based on the identifier, source address,
 * and destination address. Linear search is used. It is still not optimized
 * yet. Maybe later it can be improved by using hash algorithm.
 */
extern struct clnp_fragl *clnp_find(__u8 *dest, __u8 *src
						    , struct clnp_segment *seg);

/**
 * clnp_new_pkt
 *
 * Create a new fragment list with the given destination and source address
 * as well as other properties of the new fragment list supplied with the other
 * parameters.
 */
extern struct clnp_fragl *clnp_new_pkt(struct sk_buff *skb, __u8 *dest
					 , __u8 *src, struct clnp_segment *seg);

/**
 * clnp_comp_frag - inserts a segment into its place overcoming overlap
 */
extern void clnp_insert_frag(struct clnp_fragl *cfl, struct sk_buff *skb
						    , struct clnp_segment *seg);

/**
 * clnp_comp_frag - checks whether all segments have been received completely
 */
extern struct sk_buff *clnp_comp_frag(struct clnp_fragl *cfh
						       , unsigned short totlen);

/**
 * clnp_frag_destroy - removes a fragment list and its fragments
 *
 * The fragment list is also removed from the queue.
 * This function is called after all the segments have been reconstructed or
 * when the timer has expired.
 */
extern void clnp_frag_destroy(struct clnp_fragl *cfh);

/**
 * clnp_frag_expires - called when the reassembly timer expired
 */
extern void clnp_frag_expires(unsigned long data);

/**
 * compare_addr - compares whether the given CLNP addresses are exactly the same
 */
extern int compare_addr(__u8 *addr1, __u8 *addr2);

/**
 * concatenate - concatenates a portion data from a segment into a skb buffer
 *
 * This skb is the buffer that will be returned when all segments has been
 * received
 */
extern void concatenate(struct sk_buff *skb, struct clnp_frag *cfr);

/*
 * Functions provided by clnp_util.c
 */

/**
 * clnp_hdr - returns the CLNP header part of an skb
 */
extern __always_inline struct clnphdr *clnp_hdr(struct sk_buff *skb)
{
	return (struct clnphdr *) skb->h.raw;
}

/**
 * clnp_decompose - assigns the value from skb->nh.raw into clnph
 */
extern void clnp_decompose(struct sk_buff *skb, struct clnphdr *clnph);

/**
 * set_flag - returns the value for CLNP header flag field
 */
extern __always_inline __u8 set_flag(__u8 sp, __u8 ms, __u8 er, __u8 type)
{
	return sp << 7 | ms << 6 | er << 5 | type;
}

/**
 * clnp_decrease_ttl - decreases the value of TTL field in CLNP header by one
 */
extern __always_inline __u8 clnp_decrease_ttl(struct clnphdr *clnph)
{
	return --(clnph->cnf_ttl);
}

/**
 * merge_chars_to_short - returns unsigned short from two unsigned characters
 *
 * The primary objective is to take care of the endian-ness of the underlying
 * machine.
 */
extern unsigned short merge_chars_to_short(__u8 idx_msb, __u8 idx_lsb);

/**
 * print_header_clnp - prints the CLNP header general values
 *
 * This function is the same as print_header() but takes different type of
 * parameter
 */
extern void print_header_clnp(struct clnphdr *clnph);

/**
 * print_header_segment - prints the header segmentation part values
 *
 * This function is the same as print_segment() but takes different type of
 * parameter
 */
extern void print_header_segment(struct clnp_segment *seg);

/**
 * print_header_options - prints the header optional part values
 */
extern void print_header_options(struct clnp_options *opt);

/**
 * print_data_hex - prints the payload of a CLNP PDU in a neat form
 */
extern void print_data_hex(struct sk_buff *skb);

#endif /* _NET_CLNP_H */
