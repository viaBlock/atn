// SPDX-License-Identifier: GPL-2.0
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// include ATN protocol defines
#include <linux/atn.h>

#define scnprintf snprintf
#define min(x,y)   ((x) < (y) ? (x) : (y))

#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define PORT	        58971
#define MAXSIZE         CLNP_MTU

const char hex_asc[] = "0123456789abcdef";

#define PRINT_OUT_BUFFERS   1

static const char* local = NULL;
static const char* remote = NULL;
static int is_server;
static int is_atn = 1;
static int is_raw = 1;
static int is_debug = 0;

static ssize_t msglen = MAXSIZE;
static uint8_t msg[MAXSIZE];

static void handle_error(const char* msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

static const uint8_t nsap_addr_prefix[] = { 47, 00, 27, 81, 47, 42, 52, 00, 00, 00, 00 };
static const char nsap_prefix[] = "470027+8147425200000000";

/**
 * hex_dump_to_buffer - convert a blob of data to "hex ASCII" in memory
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @linebuf: where to put the converted data
 * @linebuflen: total size of @linebuf, including space for terminating NUL
 * @ascii: include ASCII after the hex output
 *
 * hex_dump_to_buffer() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of uint8_t data, hex_dump_to_buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output is always NUL-terminated.
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1,
 *			linebuf, sizeof(linebuf), true);
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 */
static void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,
			int groupsize, char *linebuf, size_t linebuflen,
			int ascii)
{
	const uint8_t *ptr = buf;
	uint8_t ch;
	int j, lx = 0;
	int ascii_column;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (!len)
		goto nil;
	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;
	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	switch (groupsize) {
	case 8: {
		const uint64_t *ptr8 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%16.16llx", j ? " " : "",
					(unsigned long long)*(ptr8 + j));
		ascii_column = 17 * ngroups + 2;
		break;
	}

	case 4: {
		const uint32_t *ptr4 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%8.8x", j ? " " : "", *(ptr4 + j));
		ascii_column = 9 * ngroups + 2;
		break;
	}

	case 2: {
		const uint16_t *ptr2 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%4.4x", j ? " " : "", *(ptr2 + j));
		ascii_column = 5 * ngroups + 2;
		break;
	}

	default:
		for (j = 0; (j < len) && (lx + 3) <= linebuflen; j++) {
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			linebuf[lx++] = hex_asc_lo(ch);
			linebuf[lx++] = ' ';
		}
		if (j)
			lx--;

		ascii_column = 3 * rowsize + 2;
		break;
	}
	if (!ascii)
		goto nil;

	while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
		linebuf[lx++] = ' ';
	for (j = 0; (j < len) && (lx + 2) < linebuflen; j++) {
		ch = ptr[j];
		linebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	linebuf[lx++] = '\0';
}

/**
 * print_hex_dump - print a text hex dump to syslog for a binary blob of data
 * @level: kernel log level (e.g. KERN_DEBUG)
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @rowsize: number of bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print at a time (1, 2, 4, 8; default = 1)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @ascii: include ASCII after the hex output
 *
 * Given a buffer of uint8_t data, print_hex_dump() prints a hex + ASCII dump
 * to the kernel log at the specified kernel log level, with an optional
 * leading prefix.
 *
 * print_hex_dump() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 * print_hex_dump() iterates over the entire input @buf, breaking it into
 * "line size" chunks to format and print.

 *
 * E.g.:
 *   print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS,
 *		    16, 1, frame->data, frame->len, true);
 *
 * Example output using %DUMP_PREFIX_OFFSET and 1-byte mode:
 * 0009ab42: 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 * Example output using %DUMP_PREFIX_ADDRESS and 4-byte mode:
 * ffffffff88089af0: 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.
 */
static void print_hex_dump(const char *prefix_str, int prefix_type,
			int rowsize, int groupsize,
			const void *buf, size_t len, int ascii)
{
	const uint8_t *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case 1:
			printf("%s%p: %s\n", prefix_str, ptr + i, linebuf);
			break;
		case 2:
			printf("%s%.8x: %s\n", prefix_str, i, linebuf);
			break;
		default:
			printf("%s%s\n", prefix_str, linebuf);
			break;
		}
	}
}

/**
 * print_hex_dump_bytes - shorthand form of print_hex_dump() with default params
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @prefix_type: controls whether prefix of an offset, address, or none
 *  is printed (%DUMP_PREFIX_OFFSET, %DUMP_PREFIX_ADDRESS, %DUMP_PREFIX_NONE)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 *
 * Calls print_hex_dump(), with log level of KERN_DEBUG,
 * rowsize of 16, groupsize of 1, and ASCII output included.
 */
static void print_hex_dump_bytes(const char *prefix_str, int prefix_type,
			  const void *buf, size_t len)
{
	print_hex_dump(prefix_str, prefix_type, 16, 1, buf, len, 1);
}

static void print_usage(const char *prog)
{
	printf("Usage: %s [-sidv] [-l addr] [-r addr] [-m len] [msg]\n", prog);
	handle_error("  -s|--server  - start server\n"
		 "  -l|--local   - local address\n"
		 "  -r|--remote  - overwrite remote address\n"
		 "  -i|--inet    - use IPv4 stack instead of ATN\n"
		 "  -d|--dgram   - use DGRAM socket instead of RAW\n"
		 "  -v|--verbose - be verbose about data sent and received\n"
		 "  -m|--msglen  - use random date of specified len\n"
		 "  msg          - optional message to send, use full MTU if neither msg or msglen specified\n"
	);
}

static void parse_opts(int argc, char *argv[])
{
	while (1) {
		int option_index = 0;
		static const struct option lopts[] = {
			{ "server",  no_argument, 0, 0 },
			{ "local",   required_argument, 0, 0 },
			{ "remote",  required_argument, 0, 0 },
			{ "msglen",  required_argument, 0, 0 },
			{ "inet",    no_argument, 0, 0 },
			{ "dgram",   no_argument, 0, 0 },
			{ "verbose",   no_argument, 0, 0 },
			{ NULL, 0, 0, 0 },
		};
		int c;

		c = getopt_long(argc, argv, "sl:r:m:idv", lopts, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 's':
			is_server = 1;
			break;

		case 'l':
			local = strdup(optarg);
			break;

		case 'r':
			remote = strdup(optarg);
			break;

		case 'i':
			is_atn = 0;
			break;

		case 'd':
			is_raw = 0;
			break;

		case 'v':
			is_debug = 1;
			break;

		case 'm':
			msglen = atoi(optarg);
			break;
		}
	}

	if (!is_server && !remote || is_server && !local) {
		print_usage(argv[0]);
	}

	if ((optind + 1) == argc) {
		msglen = min(sizeof(msg), strlen(argv[optind]));
		memcpy(msg, argv[optind], msglen);
	} else {
		srand(PORT);
		for (int i = 0; i < MAXSIZE; ++i) {
			msg[i] = rand() % 256;
		}
	}
}

static int resolv_addr(const char* name, void* addr) {
	if (addr && name) {
		if (is_atn) {
			int i;
			struct atn_addr* atn = addr;
			if (strlen(name) != NSAP_ADDR_LEN * 2 + 1) {
				printf("NSAP address: %s\n", name);
				handle_error("incorrect NSAP address, exiting\n");
			}
			if (strncmp(name, nsap_prefix, sizeof(nsap_prefix) - 1) != 0) {
				printf("NSAP address: %s\n", name);
				handle_error("couldn't resolve NSAP address, exiting\n");
			}

			memset(atn->s_addr, 0, sizeof(atn->s_addr));
			memcpy(atn->s_addr, nsap_addr_prefix, sizeof(nsap_addr_prefix));
			//resolve node address, last bytes are MAC address in fact
			// first +1 is due to '+' in the address
			for (i = sizeof(nsap_addr_prefix); i < NSAP_ADDR_LEN; ++i) {
				uint8_t upper = tolower(name[i * 2 + 1]);
				uint8_t lower = tolower(name[i * 2 + 1 + 1]);
				if (!isxdigit(upper) || !isxdigit(lower)) {
					printf("NSAP address: %s\n", name);
					handle_error("bad NSAP address, exiting\n");
				}
				uint8_t digit = 0;
				if (isdigit(upper))
					digit |= upper - '0';
				else
					digit |= upper - 'a' + 10;
				digit <<= 4;
				if (isdigit(lower))
					digit |= lower - '0';
				else
					digit |= lower - 'a' + 10;
				atn->s_addr[i] = digit;
			}
			printf("resolving NSAP address '%s', got binary:\n", name);
			//print_hex_dump("NSAP in BIN:", 1, sizeof(atn->s_addr), 1, atn->s_addr, sizeof(atn->s_addr), 0);
			return 1;
		} else {
			return inet_aton(name, addr);
		}
	}

	return 0;
}

int main(int argc, char *argv[]) {
	int sockfd;
	struct sockaddr_atn local_addr_atn, remote_addr_atn;
	struct sockaddr_in local_addr_in, remote_addr_in;
	const socklen_t sock_len = is_atn ? sizeof(local_addr_atn) : sizeof(local_addr_in);
	struct sockaddr* const local_addr = is_atn ? (struct sockaddr*)&local_addr_atn : (struct sockaddr*)&local_addr_in;
	struct sockaddr* const remote_addr = is_atn ? (struct sockaddr*)&remote_addr_atn : (struct sockaddr*)&remote_addr_in;

	parse_opts(argc, argv);

	memset(local_addr, 0, sock_len);
	memset(remote_addr, 0, sock_len);

	if (is_atn) {
		// Filling server information
		struct sockaddr_atn* addr = (struct sockaddr_atn*)local_addr;

		if (local) {
			addr->satn_family = AF_ATN;
			resolv_addr(local, &addr->satn_addr);
			memcpy(addr->satn_mac_addr, addr->satn_addr.s_addr + NSAP_ADDR_LEN - ETH_ALEN, sizeof(addr->satn_mac_addr));
		}

		if (remote) {
			addr = (struct sockaddr_atn*)remote_addr;
			addr->satn_family = AF_ATN;
			resolv_addr(remote, &addr->satn_addr);
			memcpy(addr->satn_mac_addr, addr->satn_addr.s_addr + NSAP_ADDR_LEN - ETH_ALEN, sizeof(addr->satn_mac_addr));
		}
	} else {
		struct sockaddr_in* addr = (struct sockaddr_in*)local_addr;

		if (local) {
			addr->sin_family = AF_INET; // IPv4
			addr->sin_port = htons(is_server ? PORT : PORT - 1);
			resolv_addr(local, &addr->sin_addr);
		}

		if (remote) {
			addr = (struct sockaddr_in*)remote_addr;
			addr->sin_family = AF_INET; // IPv4
			addr->sin_port = htons(is_server ? PORT -1 : PORT);
			resolv_addr(remote, &addr->sin_addr);
		}
	}

	// Creating socket file descriptor
	sockfd = socket(is_atn ? AF_ATN : AF_INET, is_raw ? SOCK_RAW : SOCK_DGRAM, is_atn ? 0 : IPPROTO_ICMP);
	if (sockfd < 0) {
		handle_error("socket creation failed");
	}

	// Bind the socket with the server address
	if (bind(sockfd, local_addr, sock_len) < 0) {
		handle_error("bind failed");
	}

	if (is_server) {
		while(1) {
			socklen_t remote_addr_len = sock_len;
			ssize_t msg_size;

			memset(msg, 0 , sizeof(msg));

			msg_size = recvfrom(sockfd, msg, sizeof(msg), 0, remote_addr, &remote_addr_len);
			if (msg_size < 0) {
				handle_error("error from recvfrom");
			}
			printf("RECEIVED %ld bytes:\n", msg_size);
			if (is_debug)
				print_hex_dump_bytes("", 2, msg, msg_size);

			msg_size = sendto(sockfd, msg, msg_size, 0, remote_addr, remote_addr_len);
			if (msg_size < 0) {
				handle_error("error from sendto");
			}
			printf("SEND %ld bytes:\n", msg_size);
			if (is_debug)
				print_hex_dump_bytes("", 2, msg, msg_size);
		}
	} else {
		ssize_t msg_size;
		uint8_t* msg_received;

		msg_size = sendto(sockfd, msg, msglen, 0, remote_addr, sock_len);
		if (msg_size < 0) {
			handle_error("error from sendto");
		} else if (msg_size != msglen) {
			printf ("REQUESTED:%ld SENT:%ld\n", msglen, msg_size);
			handle_error("NOT ALL DATA SENT");
		}
		printf("SEND %ld bytes:\n", msg_size);
		if (is_debug)
			print_hex_dump_bytes("", 2, msg, msg_size);

		msg_received = malloc(MAXSIZE);
		if (!msg_received) {
			handle_error("can't allocate memory for receive buffer");
		}

		memset(msg_received, 0 , MAXSIZE);

		msg_size = recv(sockfd, msg_received, msg_size, 0);
		if (msg_size < 0) {
			free(msg_received);
			handle_error("error from recvfrom");
		} else if (msg_size != msglen) {
			free(msg_received);
			printf ("SENT:%ld RECEIVED:%ld\n", msglen, msg_size);
			handle_error("NOT ALL DATA RECEIVED");
		} else if (memcmp(msg_received, msg, msg_size) != 0) {
			printf("DATA MISMATCH BETWEEN SENT AND RECEIVED\n");
			print_hex_dump_bytes("", 2, msg_received, msg_size);
			handle_error("");
		}
		printf("RECEIVED %ld bytes:\n", msg_size);
		if (is_debug)
			print_hex_dump_bytes("", 2, msg, msg_size);
	}

	return 0;
}
