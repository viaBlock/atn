/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Tadeus:		- 2008/04/07:
 *				* Define struct atn_addr, sockaddr_atn, atn_sock
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_ATN_H_
#define _LINUX_ATN_H_ 1

#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#define AF_ATN   AF_IPX
#define PF_ATN   PF_IPX

/*
 * Various values for the fixed part of a CLNP header
 */
#define CLNP_VERSION	1	/* CLNP version */
#define CLNP_NLPID	0x81	/* CLNP network layer protocol ID */
#define INAC_NLPID	0x00	/* inactive network layer protocol ID */
#define CLNP_MAXTTL	255	/* maximum time-to-live */
#define CLNP_TTL_UNITS	2	/* 500 miliseconds */
#define CLNP_FIX_LEN	51	/* the minimum length of a CLNP header */
#define CLNP_HDR_MAX	254	/* the maximum length of a CLNP header */

#define NSAP_ADDR_LEN	20	/* the length of the address value */

/* TODO: make sure to use correct LLC_PDU */
#define CLNP_MTU         (ETH_DATA_LEN - CLNP_HDR_MAX - 4)

struct atn_addr {
	__u8 s_addr[NSAP_ADDR_LEN];
};

struct sockaddr_atn {
	sa_family_t	satn_family;
	struct atn_addr	satn_addr;
	unsigned char	satn_mac_addr[IFHWADDRLEN];
};

#endif
