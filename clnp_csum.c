/*
 * ATN		CLNP checksum module
 *
 * Version:
 *
 * Authors:	Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Husni Fahmi <fahmi@inn.bppt.go.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Husni Fahmi:	2007/09/18:
 *				Finished debugging clnp_check_csum()
 *		Tadeus:		2008/03/30:
 *				Fixing memory leak in clnp_check_csum() because
 *				temp was never freed as a result of using
 *				return statement in each conditional branch
 *				(the introduction of rc variable settles this)
 *				Remove the existence of `if (x == 0 && y == 0)'
 *				do nothing conditional branch by replacing it
 *				with `if (x != 0 && y != 0)' conditional branch
 *				in function clnp_adjust_csum()
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <linux/clnp.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/clnp.h>

void clnp_gen_csum(struct sk_buff *skb, int hdr_len)
{
	int c0 = 0;
	int c1 = 0;
	int x = 0;
	int y = 0;
	int hdr_idx = 0;
	__u8 *temp = NULL;

	c0 = 0;
	c1 = 0;

	temp = (unsigned char *) kmalloc(sizeof(unsigned char) * hdr_len
								  , GFP_KERNEL);
	temp = memcpy(temp, skb->nh.raw, hdr_len);

	for(hdr_idx = 0; hdr_idx < hdr_len; hdr_idx++)
	{
		c0 = (c0 + *(temp));
		c1 = (c1 + c0);

		temp++;
	}

	x = ((hdr_len - 8) * c0 - c1) % 255;
	if( x < 0 ) {
		x += 255;
	}

	y = ((hdr_len - 7) * (-c0) + c1) % 255;
	if( y < 0 ) {
		y += 255;
	}

	if( x == 0 ) {
		x = 255;
	}
	if( y == 0 ) {
		y = 255;
	}

	skb->nh.raw[IDX_CKSUM_MSB] = x;
	skb->nh.raw[IDX_CKSUM_LSB] = y;
}

int clnp_check_csum(struct sk_buff *skb, int hdr_len)
{
	__u64 c0 = 0;
	__u64 c1 = 0;
	int hdr_idx = 0;
	__u8 *temp = NULL;
	unsigned int x = 0;
	unsigned int y = 0;
	int rc = 0;

	temp = (unsigned char *) kmalloc(sizeof(unsigned char) * hdr_len
								  , GFP_KERNEL);
	temp = memcpy(temp, skb->nh.raw, hdr_len);

	/*
	 * If both octets contain 0, the checksum calculation has suceeded.
	 * If either but not both octets contain 0, checksum fails.
	 */
	if ((skb->nh.raw[IDX_CKSUM_LSB] == 0)
					 && (skb->nh.raw[IDX_CKSUM_MSB] == 0)) {
		rc = 1;
	} else if ((skb->nh.raw[IDX_CKSUM_LSB] == 0)
					 && (skb->nh.raw[IDX_CKSUM_MSB] != 0)) {
		rc = 0;
	} else if ((skb->nh.raw[IDX_CKSUM_LSB] != 0)
					 && (skb->nh.raw[IDX_CKSUM_MSB] == 0)) {
		rc = 0;
	} else {
		c0 = c1 = 0;
		x = y = 0;
		for (hdr_idx = 0; hdr_idx < hdr_len; hdr_idx++) {
			c0 = (c0 + *temp);
			c1 = (c1 + c0);
			temp++;
		}

		x = (unsigned int) c0 % 255;
		y = (unsigned int) c1 % 255;

		if (x || y) {
			rc = 0;
		} else {
			rc = 1;
		}
	}

	kfree(temp);
	return rc;
}

void clnp_adjust_csum(struct sk_buff *skb, int idx_changed, __u8 new_value
							       , __u8 old_value)
{
	int z = 0;
	int x = 0;
	int y = 0;
	int idx_msb = 0;
	int idx_lsb = 0;
	idx_msb = 7;
	idx_lsb = 8;

	z = new_value - old_value;
	x = skb->nh.raw[IDX_CKSUM_MSB];
	y = skb->nh.raw[IDX_CKSUM_LSB];

	/*
	 * If both checksum values equal zero, do nothing.
	 * If either checksum value equals zero, checksum is incorrect.
	 * Else, calculate the new value of x and y
	 */
	if (x != 0 && y != 0) {
		x = ((idx_changed - idx_msb - 1) * z + x) % 255;
		if (x < 0) {
			x += 255;
		}

		y = ((idx_msb - idx_changed) * z + y) % 255;
		if (y < 0) {
			y += 255;
		}

		if (x == 0) {
			x = 255;
		}
		if (y == 0) {
			y = 255;
		}

		skb->nh.raw[IDX_CKSUM_MSB] = x;
		skb->nh.raw[IDX_CKSUM_LSB] = y;
	} else if ((x == 0 && y != 0) || (x != 0 && y == 0)) {
		clnp_discard(skb,GEN_BADCSUM);
	}
}
