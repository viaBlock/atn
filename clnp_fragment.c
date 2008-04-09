/*
 * ATN		CLNP fragment module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		2008/04/06:
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
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <net/clnp.h>

/* clnp_fragl_nqueues holds the number of fragment lists currently maintained
						 in the linked list structure */
static int clnp_fragl_nqueues = 0;

/* clnp_frags holds the last fragment list in the queue */
static struct clnp_fragl *clnp_frags = NULL;

void clnp_frag_destroy(struct clnp_fragl *cfh)
{
	struct clnp_frag *frag_p = NULL;
	struct clnp_frag *next_p = NULL;
	struct clnp_fragl *scan = NULL;

	printk(KERN_INFO "Entering clnp_frag_destroy()\n");

	/* remove cfh from the list of fragmented PDUs */
	printk(KERN_INFO "Unlink the fragment list from the queue\n");
	if (clnp_frags == cfh) {
		clnp_frags = cfh->cfl_next;
	} else {
		for (scan = clnp_frags; scan != NULL; scan = scan->cfl_next) {
			if (scan->cfl_next == cfh) {
				scan->cfl_next = cfh->cfl_next;
				break;
			}
		}
	}
	--clnp_fragl_nqueues;

	frag_p = cfh->cfl_frags;
	while (frag_p != NULL) {
		next_p = frag_p->cfr_next;
		kfree(frag_p);
		frag_p = next_p;
	}

	printk(KERN_INFO "Fragment list discarded\n");
	kfree(cfh);

	printk(KERN_INFO "The number of CLNP Frag queues: %d\n"
							  , clnp_fragl_nqueues);
}

void clnp_frag_expires(unsigned long data)
{
	struct clnp_fragl *expired = (struct clnp_fragl *) data;
	struct clnp_frag *first_frag = expired->cfl_frags;

	printk(KERN_INFO "Reassembly timer expired for fragment ID: 0x%04X\n"
								 , expired->id);

	if (expired->complete == 1) {
		printk(KERN_INFO "The frag list is complete for fragment ID:"
						      " 0x%04X\n", expired->id);
		return;
	}

	if (first_frag->cfr_first == 0) {
		clnp_emit_er(expired->cfl_orihdr, GEN_INCOMPLETE);
	}

	clnp_frag_destroy(expired);
}

void concatenate(struct sk_buff *skb, struct clnp_frag *cfr)
{
	unsigned int fraglen = cfr->cfr_last - cfr->cfr_first + 1;
	unsigned short seg_len = 0;
	__u8 *temp_seglen = NULL;

	memcpy(skb->data, cfr->data, fraglen);
	skb->data += fraglen - 1;

	seg_len = merge_chars_to_short(skb->nh.raw[IDX_SEGLEN_MSB]
		      , skb->nh.raw[IDX_SEGLEN_LSB]) + (unsigned short) fraglen;
	temp_seglen = (unsigned char *) &seg_len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	skb->nh.raw[IDX_SEGLEN_MSB] = temp_seglen[1];
	skb->nh.raw[IDX_SEGLEN_LSB] = temp_seglen[0];
#elif defined(__BIG_ENDIAN_BITFIELD)
	skb->nh.raw[IDX_SEGLEN_MSB] = temp_seglen[0];
	skb->nh.raw[IDX_SEGLEN_LSB] = temp_seglen[1];
#else
#error Only handle little and big endian byte-orders
#endif
}

int compare_addr(__u8 *addr1, __u8 *addr2)
{
	int counter = 0;
	int indicator = 0;

	for (counter = 0; counter < 20; counter++) {
		if (addr1[counter] != addr2[counter]) {
			indicator = 1;
			break;
		}
	}

	if (indicator == 0) {
		return 1;
	} else {
		return 0;
	}
}

struct clnp_fragl *clnp_find(__u8 *dest, __u8 *src, struct clnp_segment *seg)
{
	struct clnp_fragl *cfh = NULL;

	printk(KERN_INFO "Entering clnp_find()\n");
	cfh = clnp_frags;
	while (cfh != NULL) {
		if ((cfh->id == seg->cng_id) && compare_addr(cfh->dstaddr, dest)
					   && compare_addr(cfh->srcaddr, src)) {
			printk(KERN_INFO "Fragment is found.\n");
			return cfh;
		} else {
			cfh = cfh->cfl_next;
		}
	}

	printk(KERN_INFO "Fragment is not found.\n");
	return NULL;
}

struct clnp_fragl *clnp_new_pkt(struct sk_buff *skb, __u8 *dest, __u8 *src
						     , struct clnp_segment *seg)
{
	struct clnp_fragl *cfl = NULL;

	printk(KERN_INFO "Entering clnp_new_pkt()\n");
	if(clnp_fragl_nqueues == CLNP_MAX_Q) {
		printk(KERN_INFO "Queue is full, cannot create a new fragment"
								     " list\n");
		clnp_discard(skb, REASS_INTERFERE);
	} else {
		if(skb) {
			cfl = (struct clnp_fragl *) kmalloc(
					 sizeof(struct clnp_fragl), GFP_KERNEL);
			cfl->cfl_orihdr = dev_alloc_skb(sizeof(struct sk_buff));
			cfl->cfl_orihdr->nh.raw = (unsigned char *) kmalloc(
				sizeof(unsigned char) * skb->nh.raw[IDX_HDR_LEN]
								  , GFP_KERNEL);
			memcpy(&cfl->cfl_orihdr->nh.raw[IDX_PROTO_ID]
						    , &skb->nh.raw[IDX_PROTO_ID]
						    , skb->nh.raw[IDX_HDR_LEN]);

			cfl->id = seg->cng_id;
			printk(KERN_INFO "cfl->id: %02X\n",cfl->id);

			memcpy(cfl->dstaddr, &skb->nh.raw[IDX_DEST_ADDR], 20);
			memcpy(cfl->srcaddr, &skb->nh.raw[IDX_SRC_ADDR], 20);

			cfl->cfl_ttl = skb->nh.raw[IDX_TTL];
			cfl->cfl_last = seg->cng_tot_len
						 - skb->nh.raw[IDX_HDR_LEN] - 1;
			cfl->cfl_frags = NULL;
			cfl->cfl_next = clnp_frags;
			clnp_frags = cfl;
			clnp_fragl_nqueues++;

			init_timer(&cfl->timer);
			cfl->timer.expires = jiffies + CLNP_FRAG_TIME;
			cfl->timer.data = (unsigned long) cfl;
			cfl->timer.function = clnp_frag_expires;
			add_timer(&cfl->timer);
			return cfl;
		} else {
			clnp_discard(skb, GEN_INCOMPLETE);
  		}
	}

	return 0;
}

void clnp_insert_frag(struct clnp_fragl *cfl, struct sk_buff *skb
						     , struct clnp_segment *seg)
{
	struct clnp_frag *cf_pre = NULL;
	struct clnp_frag *cf = NULL;
	struct clnp_frag *cf_post = NULL;
	unsigned short first = 0;
	unsigned short last = 0;
	unsigned short fraglen = 0;
	unsigned short hdrlen = 0;
	unsigned short start = 0;
	unsigned short overlap = 0;

	printk(KERN_INFO "Entering clnp_insert_frag()\n");

	first = seg->cng_off;
	fraglen = merge_chars_to_short(skb->nh.raw[IDX_SEGLEN_MSB]
						  , skb->nh.raw[IDX_SEGLEN_LSB])
				    - (unsigned short) skb->nh.raw[IDX_HDR_LEN];
	last = first + fraglen - 1;

	/* if it is not the last fragment and the fragment is not modulus 8,
					 we shave the fragment into modulus 8 */
	if (skb->nh.clnph->cnf_flag & CNF_MS) {
		if ((last + 1) % 8 != 0) {
			printk(KERN_INFO "The fragment is not modulus 8\n");
			printk(KERN_INFO "Before the fragment is shaved, last"
						 " offset is %d\n", (int) last);
			last = (((last + 1) / 8) * 8) - 1;
			printk(KERN_INFO "After the fragment is shaved, last"
						 " offset is %d\n", (int) last);
		}
	}

	if (cfl->cfl_frags != NULL) {
		cf = cfl->cfl_frags;
		while (cf != NULL) {
			if (cf->cfr_first >= first) {
				cf_post = cf;
				break;
			}
			cf_pre = cf;
			cf = cf->cfr_next;
		}

		if (cf_pre != NULL) {
			if (cf_pre->cfr_last >= first) {
				overlap = cf_pre->cfr_last - first + 1;
				printk(KERN_INFO "Fraglen: %d\n", fraglen);
				if (overlap >= fraglen) {
					printk(KERN_INFO "All part of the new"
						 " received segment is included"
						     " in the previous adjacent"
								  " segment\n");
					kfree_skb(skb);
					return;
				} else {
					printk(KERN_INFO "Only partial part of"
						     " the new received segment"
						   " overlaps with the previous"
							 " adjacent segment\n");
					printk(KERN_INFO "Overlap with previous"
					       " fragment: %d bytes\n",overlap);
					first += overlap;
				}
			}
		}
		printk(KERN_INFO "Test\n");
		for (cf = cf_post; cf != NULL; cf = cf->cfr_next) {
			if (cf->cfr_first <= last) {
				unsigned short overlap = last - cf->cfr_first
									    + 1;
				printk(KERN_INFO "Fraglen: %d\n", fraglen);
				if (overlap >= fraglen) {
					printk(KERN_INFO "All part of the new"
						 " received segment is included"
							 " in the next adjacent"
								  " segment\n");
					kfree_skb(skb);
					return;
				} else {
					printk(KERN_INFO "Only partial part of"
						     " the new received segment"
						       " overlaps with the next"
							 " adjacent segment\n");
					printk(KERN_INFO "Overlap with next"
					      " fragment: %d bytes\n", overlap);
					last -= overlap;
				}
			}
		}
	}

	/* Insert the new fragment between cf_pre & cf_post */
	cf = (struct clnp_frag *) kmalloc(sizeof(struct clnp_frag), GFP_KERNEL);
	hdrlen = (unsigned short) skb->nh.raw[IDX_HDR_LEN];
	cf->data = (unsigned char *) kmalloc(sizeof(unsigned char)
					      * (last - first + 1), GFP_KERNEL);
	start = hdrlen + overlap;
	memcpy(cf->data, &skb->nh.raw[start], last - first + 1);

	cf->cfr_first = first;
	cf->cfr_last = last;
	if (last > cfl->cfl_last) {
		cfl->cfl_last = last;
	}
	cf->cfr_next = cf_post;
	if (cf_pre == NULL) {
		cfl->cfl_frags = cf;
	} else {
		cf_pre->cfr_next = cf;
	}
}

struct sk_buff *clnp_comp_frag(struct clnp_fragl *cfh, unsigned short totlen)
{
	struct sk_buff *complete_skb = dev_alloc_skb(sizeof(struct sk_buff));
	struct clnp_frag *cf = cfh->cfl_frags;
	unsigned short hdr_len
			= (unsigned short) cfh->cfl_orihdr->nh.raw[IDX_HDR_LEN];
	__u8 *temp_seglen = (unsigned char *) &hdr_len;
	int start_offset = cf->cfr_first;
	int last_offset = 0;

	printk(KERN_INFO "Entering clnp_comp_frag()\n");
	complete_skb->data = (unsigned char *) kmalloc(sizeof(unsigned char)
						  * (totlen + 100), GFP_KERNEL);
	complete_skb->nh.clnph = (struct clnphdr *) complete_skb->data;
	memcpy(complete_skb->data, &cfh->cfl_orihdr->nh.raw[IDX_PROTO_ID]
								     , hdr_len);
	complete_skb->data += hdr_len;

#if defined(__LITTLE_ENDIAN_BITFIELD)
	complete_skb->nh.raw[IDX_SEGLEN_MSB] = temp_seglen[1];
	complete_skb->nh.raw[IDX_SEGLEN_LSB] = temp_seglen[0];
#elif defined(__BIG_ENDIAN_BITFIELD)
	complete_skb->nh.raw[IDX_SEGLEN_MSB] = temp_seglen[0];
	complete_skb->nh.raw[IDX_SEGLEN_LSB] = temp_seglen[1];
#else
#error Only handle little and big endian byte-orders
#endif

	while (cf != NULL) {
		struct clnp_frag *cf_next = cf->cfr_next;

		if (cf_next == NULL) {
			if (cf->cfr_first == (last_offset + 1)) {
				last_offset = cf->cfr_last;
				concatenate(complete_skb, cf);
			}
		} else {
			if ((cf->cfr_last == (cf_next->cfr_first - 1))
							  && (cf_next!= NULL)) {
				last_offset = cf->cfr_last;
				concatenate(complete_skb, cf);
			}
		}
		cf = cf->cfr_next;
	}

	if ((start_offset == 0) && (last_offset == cfh->cfl_last)) {
		cfh->complete = 1; /* set complete indicator to true */
		printk(KERN_INFO "All fragments have been received\n");
		printk(KERN_INFO "The complete reassembled data:\n");
		print_data_hex(complete_skb);
		del_timer_sync(&cfh->timer);
		clnp_frag_destroy(cfh);
		return complete_skb;
	}

	printk(KERN_INFO "Fragments are not complete\n");
	kfree(complete_skb->nh.clnph);
	kfree_skb(complete_skb);
	return NULL;
}

struct sk_buff *clnp_defrag(struct sk_buff *skb, __u8 *dest, __u8 *src
						     , struct clnp_segment *seg)
{
	struct clnp_fragl *cfh = NULL;

	printk(KERN_INFO "Entering clnp_defrag()\n");

	if (clnp_frags == NULL) {
		printk(KERN_INFO "Currently there is no fragment list inside"
				    " the queue. Create a new fragment list\n");
		cfh = clnp_new_pkt(skb, dest, src, seg);
	} else {
		if ((cfh = clnp_find(dest, src, seg)) == NULL) {
			printk(KERN_INFO "Fragment List is not found\n"
						"Create a new fragment list\n");
			cfh = clnp_new_pkt(skb, dest, src, seg);
		} else {
			printk(KERN_INFO "Fragment list is found\n");
		}
	}

	if (cfh != NULL) {
		clnp_insert_frag(cfh, skb, seg);
		if ((skb = clnp_comp_frag(cfh, seg->cng_tot_len))) {
			printk(KERN_INFO "Fragments are complete\n");
			return skb;
		} else {
			printk(KERN_INFO "Fragments are not complete\n");
			return NULL;
		}
	} else {
		return NULL;
	}
}
