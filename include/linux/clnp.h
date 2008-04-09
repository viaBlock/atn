/*
 * ATN		An implementation of the CLNP/TP4 protocol suite for the LINUX
 *		operating system.  ATN is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_ATN protocol family socket handler.
 *
 * Version:
 *
 * Authors:	Pradana Atmadiputra <pradana.priyono@student.sgu.ac.id>
 * 		Melvin Rubianto <melvin.rubianto@student.sgu.ac.id>
 * 		Danny Laidi <danny.laidi@student.sgu.ac.id>
 * 		Bunga Sugiarto <bunga.sugiarto@student.sgu.ac.id>
 *		Tadeus Prastowo <eus@member.fsf.org>
 *
 * Changes (oldest at the top, newest at the bottom):
 *		Pradana:	Define clnp_fixed, clnp_segment, and
 *				clnp_address structure
 *  		Melvin:		Define parameter type and parameter value for
 *				the option part of CLNP
 *		Danny:		Define the extra variables (FIXED_LEN, ADDR_LEN,
 *				SEG_LEN, etc.)
 *		Danny:		Define general constant variable in header fixed
 *				part (CLNPVERSION, NLPID, MAXTTL)
 *		Danny:		Define mask for CLNP Flag Fields
 *		Danny:		Define CLNP packet types
 * 		Danny:		Define CLNP option structure
 *    		Bunga:		Define CLNP error codes
 *		Bunga:		Define CLNP header structure
 *		Bunga:		Add big and little endian condition inside
 *				clnp_fixed
 *		Tadeus:		2008/03/27:
 *				Clean up the code and notice that:
 *				- clnp_fixed and clnp_address structures have
 *				  been combined into clnphdr structure
 *				- FIXED_LEN has gone
 *				Move in clnp_fragl and clnp_frag from
 *				clnp_fragment.c to make all data structures
 *				available in one place
 *				2008/03/30:
 *				Change the way each field in a struct is
 *				commented; from comments inside the struct to
 *				comments before the struct to follow Linux
 *				coding style guideline (kernel-doc nano-HOWTO)
 *				2008/04/06:
 *				Change CNF_ERR_OK to CNF_ER, CNF_MORE_SEGS to
 *				CNF_MS, and CNF_SEG_OK to CNF_SP for better mask
 *				names
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_CLNP_H
#define _LINUX_CLNP_H

#include <asm/types.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/types.h>

/*
 * Value for extra variables
 */
#define MIN_HDR_LEN 51		/* the minimum total length of header */
#define MAX_HDR_LEN 254		/* the maximum value of length indicator */
#define CLNP_ADDR_LEN 20	/* the length of the address value */
#define FA_LEN MIN_HDR_LEN	/* the length of fixed + address part */
#define SEG_LEN 6		/* the total length of segmentation part */
#define CLNP_OPTIONS 8		/* the number of option parameter codes */
#define REASON_LEN 4		/* the length of the reason for discard */

/*
 * Variable value of fixed part
 */
#define CLNPVERSION 1		/* CLNP version */
#define NLPID 0x81		/* CLNP network layer protocol ID */
#define INLP 0x00		/* inactive network layer protocol */
#define MAXTTL 255		/* maximum time-to-live */
#define CLNP_TTL_UNITS 2	/* 500 miliseconds */
#define CLNP_FIX_LEN 51
#define CLNP_HDR_MAX 254
#define CLNP_CSUM_LSB_IDX 8	/* Checksum parameter low significant byte is
				 * located in the 8th index (9th octet) of clnp
				 * header
				 */
#define CLNP_CSUM_MSB_IDX 7	/* Checksum parameter low significant byte is
				 * located in the 7th index (8th octet) of clnp
				 * header
				 */

/*
 * Reassembly variables
 */
#define CLNP_MAX_Q 64			/* maximum CLNP queues */
#define CLNP_FRAG_TIME (30 * HZ)	/* fragment lifetime */

/*
 * Mask for CLNP Flag field
 */
#define CNF_TYPE 0x1F
#define CNF_ER 0x20
#define CNF_MS 0x40
#define CNF_SP 0x80

/*
 * CLNP packet types: this is defined from the last 5 bits in the Flag field
 * inside fixed part of PDU
 */
#define CLNP_DT 0x1C	/* Data Protocol Data Unit: normal data */
#define CLNP_MD 0x1D	/* Multicast Data PDU */
#define CLNP_ER 0x01	/* Error Report PDU */
#define CLNP_ERQ 0x1E	/* Echo Request PDU */
#define CLNP_ERP 0x1F	/* Echo Reply PDU */

/*
 * Field values of ATN NSAP (Network Service Access Point) address format
 * Read the comment as (field name: semantic of the value)
 */
#define AFI 0x2F		/* authority and format identifier: ISO 6523 ICD
				 * IDI and binary DSP format
				 */
#define IDI_1 0x00		/* 1st byte initial domain identifier:
#define IDI_2 0x1b		 * 2nd byte initial domain identifier:
				 *				ATN NSAP address
				 */
#define VER_G_AINSC 0x01	/* version:	ground AINSC NSAP address
#define VER_M_AINSC 0x41	 * 		mobile AINSC NSAP address
#define VER_G_ATSC 0x81		 * 		ground ATSC NSAP address
#define VER_M_ATSC 0xC1		 * 		mobile ATSC NSAP address
				 */
#define RDF 0x00		/* routing domain format: unassigned */

/*
 * Optional part
 */

/* Parameter for the optional part */
#define CLNPOPT_PC_PAD 0xCC		/* padding */
#define CLNPOPT_PC_SEC 0xC5		/* security */
#define CLNPOPT_PC_SRCROUTE 0xC8	/* source routing */
#define CLNPOPT_PC_ROR 0xCB		/* recording of route */
#define CLNPOPT_PC_QOS 0xC3		/* quality of service */
#define CLNPOPT_PC_PRIOR 0xCD		/* priority */
#define CLNPOPT_PC_PBSC 0xC4		/* prefix based scope control */
#define CLNPOPT_PC_RSC 0xC6		/* radius scope control */

/* Parameter value for Security Option -- if cno_code equals to 0xC5 */
#define SEC_RESERVED 0x00		/* reserved */
#define SEC_SRCADDRSPECIFIC 0x40	/* source address specific */
#define SEC_DESADDRSPECIFIC 0x80	/* destination address specific */
#define SEC_GLOBALUNIQUE 0xC0		/* globally unique */

/* Parameter value for Source Routing Option -- if cno_code equals to 0xC8 */
#define SRCROUTE_RESERVED 0x00		/* reserved */
#define SRCROUTE_COMPLETESRCROUTE 0x01	/* complete source routing */
#define SRCROUTE_PARTIALSRCROUTE 0x02	/* partial source routing */

/* Parameter value for Recording of Route Option -- if cno_code equals to 0xCB
 */
#define ROR_PARTIAL 0x00 	/* partial recording of route in progress */
#define ROR_COMPLETE 0x01	/* complete recording of route in progress */
#define ROR_PARTIAL_TS 0x02	/* partial recording of route in progress
				 * (with timestamps)
				 */
#define ROR_COMPLETE_TS	0x03	/* complete recording of route in progress
				 * (with timestamps)
				 */

/* Parameter value for QoS maintenance -- if cno_code equals to 0xC3 */
#define QOS_GLOBAL 0x00			/* globally unique with strong
					 * forwarding
					 */
#define QOS_SRCADDRSPECIFIC 0x40	/* source address specific */
#define QOS_DESADDRSPECIFIC 0x80	/* destination address specific */
#define QOS_GLOBALUNIQUEWEAK 0xC0	/* globally unique with weak forwarding
					 */

/*
 * PDU error codes
 */

/* Parameter code for `Reason for Discard' */
#define REASON_DISCARD 0xC1	/* reason for discard */

/* General errors */
#define GEN_NOREAS 0x00		/* reason not specified */
#define GEN_PROTOERR 0x01	/* protocol procedure error */
#define GEN_BADCSUM 0x02	/* incorrect checksum */
#define GEN_CONGEST 0x03	/* PDU discarded due to congestion */
#define GEN_HDRSYNTAX 0x04	/* header syntax error */
#define GEN_SEGNEEDED 0x05	/* need segmentation but not allowed */
#define GEN_INCOMPLETE 0x06	/* incomplete PDU received */
#define GEN_DUPOPT 0x07		/* duplicate option */
#define GEN_UNKNOWN 0x08	/* unknown PDU Type */

/* Address errors */
#define ADDR_DESTUNREACH 0x80	/* destination address unreachable */
#define ADDR_DESTUNKNOWN 0x81	/* destination address unknown */

/* Source routing errors */
#define SRCRT_UNSPECERR	0x90	/* unspecified source routing error */
#define SRCRT_SYNTAX 0x91	/* syntax error in source routing field */
#define SRCRT_UNKNOWNADDR 0x92	/* unknown address in source routing field */
#define SRCRT_BADPATH 0x93	/* path not acceptable */

/* Lifetime errors */
#define TTL_EXPTRANSIT 0xA0	/* lifetime expired while PDU in transit */
#define TTL_EXPREASS 0xA1	/* lifetime expired during reassembly */

/* PDU discarded because of */
#define DISC_UNSUPPOPT 0xB0	/* unsupported option not specified */
#define DISC_UNSUPPVERS 0xB1	/* unsupported protocol version */
#define DISC_UNSUPPSECURE 0xB2	/* unsupported security option */
#define DISC_UNSUPPSRCRT 0xB3	/* unsupported source routing option */
#define DISC_UNSUPPRECRT 0xB4	/* unsupported recording of route option */
#define DISC_UNAVAILQOS	 0xB5	/* unsupported or unavailable QoS */

/* Reassembly errors */
#define REASS_INTERFERE 0xC0	/* reassembly interference */
#define CLNP_ERRORS 24		/* amount of PDU error codes */

/**
 * struct clnphdr - CLNP header
 * @cnf_proto_id: network layer protocol identifier
 * @cnf_hdr_len: length indicator
 * @cnf_vers: version/protocol ID extension
 * @cnf_ttl: lifetime
 * @cnf_flag: SP, MS, E/R, PDU type
 * @cnf_seglen: segment length
 * @cnf_cksum_msb: checksum - most significant byte
 * @cnf_cksum_lsb: checksum - least significant byte
 * @dest_len: destination address length indicator
 * @dest_addr: destination address
 * @src_len: source address length indicator
 * @src_addr: source address
 */
struct clnphdr {
	__u8 cnf_proto_id;
	__u8 cnf_hdr_len;
	__u8 cnf_vers;
	__u8 cnf_ttl;
	__u8 cnf_flag;
	__be16 cnf_seglen;
	__u8 cnf_cksum_msb;
	__u8 cnf_cksum_lsb;
	__u8 dest_len;
	__u8 dest_addr[CLNP_ADDR_LEN];
	__u8 src_len;
	__u8 src_addr[CLNP_ADDR_LEN];
};

/*
 * In CLNP header, each field begins at the following n-th octet:
 */
#define IDX_PROTO_ID	0
#define IDX_HDR_LEN	1
#define IDX_VERS	2
#define IDX_TTL		3
#define IDX_FLAG	4
#define IDX_SEGLEN_MSB	5
#define IDX_SEGLEN_LSB	6
#define	IDX_CKSUM_MSB	7
#define IDX_CKSUM_LSB	8
#define IDX_DEST_LEN	9
#define IDX_DEST_ADDR	10
#define IDX_SRC_LEN	30
#define IDX_SRC_ADDR	31
#define IDX_NEXT_HDR	51

/**
 * struct clnp_segment
 * @cng_id: data unit identifier
 * @cng_off: segment offset
 * @cng_tot_len: total length
 */
struct clnp_segment {
	__be16 cng_id;
	__be16 cng_off;
	__be16 cng_tot_len;
};

/**
 * struct clnp_options
 * @cno_code: parameter code
 * @cno_len: parameter length
 * @cno_value: parameter value
 */
struct clnp_options {
	__u8 cno_code;
	__u8 cno_len;
	unsigned char *cno_value;
};

/**
 * struct clnp_frag
 * @cfr_first: offset of the first byte of this fragment
 * @cfr_last: offset of the last byte of this fragment
 * @data: pointer to the data part of this fragment
 * @cfr_next: pointer to the next fragment in the list
 *
 * This structure contains the offset of the first and last byte of
 * the fragment as well as a pointer to the data (an mbuf chain) of the
 * fragment.
 */
struct clnp_frag {
	unsigned int cfr_first;
	unsigned int cfr_last;
	__u8 *data;
	struct clnp_frag *cfr_next;
};

/**
 * struct clnp_fragl - CLNP fragment reassembly structure
 * @id: data unit identifier
 * @dstaddr: destination address of the packet
 * @srcaddr: source address of the packet
 * @cfl_ttl: current TTL of the packet
 * @cfl_last: offset of the last byte of the packet
 * @complete: indicator if the fragl is complete
 * @cfl_orihdr: pointer to the original header of the packet
 * @cfl_next: pointer to next packet being reassembled
 * @cfl_frags: linked list of fragments for packet
 * @cfl timer: reassembly timer for this list
 *
 * All packets being reassembled are linked together as a linked list of
 * clnp_fragl structure. Each clnp_fragl structure contains a pointer to the
 * original CLNP packet header as well as a list of packet fragments. Each
 * clnp_fragl also structure contains a linked list of clnp_fragl structures.
 */
struct clnp_fragl {
	__u16 id;
	__u8 dstaddr[CLNP_ADDR_LEN];
	__u8 srcaddr[CLNP_ADDR_LEN];
	__u8 cfl_ttl;
	__u16 cfl_last;
	__u8 complete;
	struct sk_buff *cfl_orihdr;
	struct clnp_fragl *cfl_next;
	struct clnp_frag *cfl_frags;
	struct timer_list timer;
};

#endif /* _LINUX_CLNP_H */
