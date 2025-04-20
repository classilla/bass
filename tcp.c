/* TCP helpers for BASS
 * Copyright (C)2025 Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This contains several low-level helpers for setup and teardown of TCP
 * connections.
 *
 * tcp_total32() is a very stupid, very simple 32-bit add that assumes
 * nothing about endianness or native register size. It adds a 16-bit
 * increment value to the value pointed to in the first argument.
 * tcp_template() creates signaling datagrams like SYN, ACK, FIN, etc.
 * You are responsible for sending them.
 * tcp_twiddle() sends a provided datagram and then waits for a requested
 * answer.
 * tcp_transmittal() takes a C-string and turns it into a TCP datagram
 * for transmission. You are responsible for sending it.
 */

#include "compat.h"
#include "tcp.h"
#include "slip.h"

/* endian independent 32-bit + 16-bit BE add, very simply implemented */
int tcp_total32(value, inc)
SCH *value;
int inc;
{
	int v, w;
#if DEBUG
fprintf(stderr, "%02x%02x%02x%02x + %04x = ",
	(unsigned int)value[0] & 0xff,
	(unsigned int)value[1] & 0xff,
	(unsigned int)value[2] & 0xff,
	(unsigned int)value[3] & 0xff, inc);
#endif

	/* add lower half */
	v = inc & 0xff;
	if (v) {
		w = value[3] & 0xff;
		if ((255 - w) < v) {
			/* it will overflow, carry */
			value[3] += v;
			value[2]++;
			if (!value[2]) { /* carry */
				value[1]++;
				if (!value[1]) {
					value[0]++;
				}
			}
		} else {
			value[3] += v;
		}
	}
	/* add upper half */
	v = (inc >> 8) & 0xff;
	if (v) {
		w = value[2] & 0xff;
		if ((255 - w) < v) {
			value[2] += v;
			value[1]++;
			if (!value[1]) {
				value[0]++;
			}
		} else {
			value[2] += v;
		}
	}

#if DEBUG
fprintf(stderr, "%02x%02x%02x%02x\n",
	(unsigned int)value[0] & 0xff,
	(unsigned int)value[1] & 0xff,
	(unsigned int)value[2] & 0xff,
	(unsigned int)value[3] & 0xff);
#endif
	return value[0]; /* will be zero if overflow occurred */
}

/* construct a TCP message packet */
int tcp_template(packet, src, dst, port, sport_h, sport_l, flags, seqno, ackno)
SCH *packet; /* packet */
SCH *src; /* our IPv4 address */
SCH *dst; /* address to connect to */
int port; /* port to connect to */
SCH sport_h; /* bogus source port, high byte */
SCH sport_l; /* bogus source port, low byte */
SCH flags; /* flag bits to send, or 2 for a simple ACK */
SCH *seqno; /* 32 bit sequence number, set to result */
SCH *ackno; /* 32 bit acknowledgement number, set to result */
{
	/* RFC 6864 indicates that pretty much nothing relies on the
         * uniqueness of the IPv4 ID field anymore. */
	int j, size;
	B16 checksum;

	slip_splat(packet, PACKET_SIZE);

	/***** IP header *****/
	/* version and length of IP header */
	packet[0] = 0x45;	/* IPv4, 5 32-bit ints == 20 bytes */

	/* TOS as DSCP and ECN: just use zero */
	packet[1] = 0x00;

	/* compute size of packet. the only option we know and support
 		is MSS, and that is only sent with SYN. */
	if (flags & 2) {
		size = 44;
	} else {
		size = 40;
	}
	packet[2] = (size >> 8) & 0xff;
	packet[3] = (size & 0x00ff);

	/* identification, big endian (see above) */
	packet[4] = rand() & 0xff;
	packet[5] = rand() & 0xff;

	/* fragmentation: none, not allowed */
	packet[6] = 0;
	packet[7] = 0;

	/* come back to the rest at the end */

	/***** TCP pseudo-header *****/
	/* we put this here so we can compute the checksum early, and then
           fill in our IP information and checksum that at the end. */

	/* source IP */
	packet[8] = src[0];
	packet[9] = src[1];
	packet[10] = src[2];
	packet[11] = src[3];

	/* destination IP */
	packet[12] = dst[0];
	packet[13] = dst[1];
	packet[14] = dst[2];
	packet[15] = dst[3];

	/* explicit zero */
	packet[16] = 0;
	/* protocol, always 6 for TCP */
	packet[17] = 6;
	/* length,  minus IP header */
	packet[18] = ((size - 20) >> 8) & 0xff;
	packet[19] = ((size - 20) & 0x00ff);

	/***** TCP payload *****/
	/* source port. don't care, but store it for checking purposes. */
	packet[20] = sport_h;
	packet[21] = sport_l;

	/* destination port, big endian */
	packet[22] = (port >> 8) & 0xff;
	packet[23] = (port & 0xff);

	/* sequence number, big endian */
	packet[24] = seqno[0];
	packet[25] = seqno[1];
	packet[26] = seqno[2];
	packet[27] = seqno[3];

	/* acknowledgement number, big endian */
	packet[28] = ackno[0];
	packet[29] = ackno[1];
	packet[30] = ackno[2];
	packet[31] = ackno[3];

	/* data offset, > 5 if SYN options present, plus reserved nybble */
	packet[32] = (flags & 2) ? 96 : 80; /* 0x60 vs 0x50 */
	/* flag bits */
	packet[33] = flags;
	/* MSS/window value, big endian */
	packet[34] = ((MSS_WINDOW >> 8) & 0xff);
	packet[35] = (MSS_WINDOW & 0xff);

	/* we'll come back to the checksum at the end */

	/* urgent pointer, not supported even if URG set, make zero */
	packet[38] = 0;
	packet[39] = 0;

	/* options. only if sending a SYN, and we only support MSS. */
	if (flags & 2) {
		packet[40] = 2;
		packet[41] = 4;
		packet[42] = packet[34];
		packet[43] = packet[35];
	}

	/* compute TCP checksum (with checksum field = 0) */
	/* including pseudo header */
	/* pad null in checksum if not even 16-bit boundary */
	checksum = slip_sum(packet + 8, size - 8);
	packet[36] = (checksum >> 8) & 0xff;
	packet[37] = (checksum & 0x00ff); 

	/***** finish IP packet ****/
	/* TTL of 64 */
	packet[8] = 64;
	
	/* protocol is TCP */
	packet[9] = 6;

	/* zero out checksum */
	packet[10] = 0;
	packet[11] = 0;

	/* source IP */
	packet[12] = src[0];
	packet[13] = src[1];
	packet[14] = src[2];
	packet[15] = src[3];

	/* destination IP */
	packet[16] = dst[0];
	packet[17] = dst[1];
	packet[18] = dst[2];
	packet[19] = dst[3];

	/* compute IP checksum (with checksum field = 0) */
	checksum = slip_sum(packet, 20);
	packet[10] = (checksum >> 8) & 0xff;
	packet[11] = (checksum & 0x00ff); 
	return size;
}

int tcp_twiddle(packet, size, waitfor, seqno, ackno, inc, err)
SCH *packet; /* packet to send */
int size; /* size of packet */
SCH waitfor; /* flags to await */
SCH *seqno; /* 32 bit sequence number, set to result */
SCH *ackno; /* 32 bit acknowledgement number, set to result */
int inc;    /* value to increase seqno by, if any */
SCH *err;    /* error buffer */
{
	int j, rsize;
	B16 checksum;
	SCH *reply;

	/* allocate reply packet */
	reply = malloc(PACKET_SIZE);
	if (!reply)
		return TCP_NOMEM;

	/* bump sequence number before we begin (already in packet) */
	/* any errors we report would be fatal anyway */
	tcp_total32(seqno, inc);

	/* we assume nothing about timers. if we get an unexpected packet, */
	/* we simply retransmit the passed packet immediately */
	for(;;) {
		if(!slip_ship(packet, size)) {
			*err = TCP_SLIP_ERROR;
			free(reply);
			return 0;
		}

		rsize = slip_slurp(reply, PACKET_SIZE);
		if (!rsize) { /* something is wrong */
			*err = TCP_SLIP_ERROR;
			free(reply);
			return 0;
		}

		/* we are expecting some sort of control packet, which all
			have an even length. kick out here since that
			simplifies the checksum portion. */
		if (rsize & 1) continue;

		j = reply[9]; /* hold for a moment */

		/* verify its checksum by reconstructing the pseudo-header */
		/* source IP */
		reply[8] = reply[12];
		reply[9] = reply[13];
		reply[10] = reply[14];
		reply[11] = reply[15];

		/* destination IP */
		reply[12] = reply[16];
		reply[13] = reply[17];
		reply[14] = reply[18];
		reply[15] = reply[19];

		/* zero, TCP, packet length */
		reply[16] = 0;
		reply[17] = 6;
		reply[18] = ((rsize - 20) >> 8) & 0xff;
		reply[19] = ((rsize - 20) & 0x00ff);
		checksum = slip_sum(reply + 8, rsize - 8);
		if (checksum) { /* RFC 1071 */
#if DEBUG
			fprintf(stderr, "tcp: checksum failed\n");
#endif
			continue;
		}

		/* fast kickouts */
		/* reject non-TCP */
		if (j != 6)
			continue;
		/* if we get an RST, cancel */
		if (reply[33] & 4) {
#if DEBUG
			fprintf(stderr, "tcp: bailing on RST\n");
#endif
			j = reply[33];
			free(reply);
			return j;
		}
		/* reject wrong port number */
		if (packet[20] != reply[22] || packet[21] != reply[23])
			continue;
		/* if we are waiting for something with an ACK in it, reject */
		/* if the ackno != ++seqno (we already bumped it) */
		if (waitfor & 16) {
			if (reply[28] != seqno[0] ||
					reply[29] != seqno[1] ||
					reply[30] != seqno[2] ||
					reply[31] != seqno[3]) {
#if DEBUG
fprintf(stderr, "tcp: unexpected seqno %02x%02x%02x%02x != %02x%02x%02x%02x\n",
(unsigned int)seqno[0] & 0xff,
(unsigned int)seqno[1] & 0xff,
(unsigned int)seqno[2] & 0xff,
(unsigned int)seqno[3] & 0xff,
(unsigned int)reply[28] & 0xff,
(unsigned int)reply[29] & 0xff,
(unsigned int)reply[30] & 0xff,
(unsigned int)reply[31] & 0xff);
#endif
				continue;
			}
		}
		/* if we're waiting for a plain ACK, but get a FIN, bail */
		if (waitfor == 16 && (reply[33] & 1)) {
#if DEBUG
			fprintf(stderr, "tcp: bailing on FIN\n");
#endif
			j = reply[33];
			free(reply);
			return j;
		}
		/* otherwise if this is not the flags we want, loop */
		/* allow PSH to succeed, since we don't use this bit */
		if (reply[33] != waitfor && (reply[33] != (waitfor | 8)))
			continue;

		/* we have a packet that purports to be our reply */
		break;
	}

	/* the reply's ackno matches our seqno, so leave that in seqno */
	/* return the reply's seqno in ackno */
	ackno[0] = reply[24];
	ackno[1] = reply[25];
	ackno[2] = reply[26];
	ackno[3] = reply[27];
	j = reply[33];
	free(reply);
	return j;
}

/* construct a TCP transmission packet with PSH+ACK */
int tcp_transmittal(packet, src, dst, port, sport_h, sport_l, seqno, ackno, str)
SCH *packet; /* packet */
SCH *src; /* our IPv4 address */
SCH *dst; /* address to connect to */
int port; /* port to connect to */
SCH sport_h; /* bogus source port, high byte */
SCH sport_l; /* bogus source port, low byte */
SCH *seqno; /* 32 bit sequence number, set to result */
SCH *ackno; /* 32 bit acknowledgement number, set to result */
SCH *str; /* string being sent, which may be empty but not NULL*/
{
	int j, size;
	B16 checksum;

	slip_splat(packet, PACKET_SIZE);
	/* version and length of IP header */
	packet[0] = 0x45;	/* IPv4, 5 32-bit ints == 20 bytes */
	/* TOS as DSCP and ECN: just use zero */
	packet[1] = 0x00;
	/* size of packet: IP, TCP and string, plus CRLF if any */
	size = 40 + strlen(str);
	if (size >= PACKET_SIZE)
		return 0;

	packet[2] = (size >> 8) & 0xff;
	packet[3] = (size & 0x00ff);

	/* identification, big endian (see above) */
	packet[4] = rand() & 0xff;
	packet[5] = rand() & 0xff;

	/* fragmentation: none, not allowed */
	packet[6] = 0;
	packet[7] = 0;

	/* come back to the rest at the end */
	/* pseudo-header follows */
	/* source IP */
	packet[8] = src[0];
	packet[9] = src[1];
	packet[10] = src[2];
	packet[11] = src[3];
	/* destination IP */
	packet[12] = dst[0];
	packet[13] = dst[1];
	packet[14] = dst[2];
	packet[15] = dst[3];
	/* explicit zero */
	packet[16] = 0;
	/* protocol, always 6 for TCP */
	packet[17] = 6;
	/* length,  minus IP header */
	packet[18] = ((size - 20) >> 8) & 0xff;
	packet[19] = ((size - 20) & 0x00ff);

	/* TCP header */
	/* source port */
	packet[20] = sport_h;
	packet[21] = sport_l;
	/* destination port, big endian */
	packet[22] = (port >> 8) & 0xff;
	packet[23] = (port & 0xff);
	/* sequence number, big endian */
	packet[24] = seqno[0];
	packet[25] = seqno[1];
	packet[26] = seqno[2];
	packet[27] = seqno[3];
	/* acknowledgement number, big endian */
	packet[28] = ackno[0];
	packet[29] = ackno[1];
	packet[30] = ackno[2];
	packet[31] = ackno[3];

	/* data offset, always 80 */
	packet[32] = 80;
	/* flag bits, always PSH + ACK */
	packet[33] = 24;
	/* MSS/window value, big endian */
	packet[34] = ((MSS_WINDOW >> 8) & 0xff);
	packet[35] = (MSS_WINDOW & 0xff);

	/* we'll come back to the checksum at the end */
	/* urgent pointer, not supported */
	packet[38] = 0;
	packet[39] = 0;

	/* text payload: append string and (if any) CRLF */
	if (strlen(str)) {
		for(j=0;j<strlen(str);j++) {
			packet[40+j] = str[j];
		}
	} else j=0;

	/* compute TCP checksum (with checksum field = 0) */
	/* including pseudo header */
	/* pad null in checksum if not even 16-bit boundary */
	if (size & 1) {
		packet[42+j] = 0;
		checksum = slip_sum(packet + 8, size - 7);
	} else {
		checksum = slip_sum(packet + 8, size - 8);
	}
	packet[36] = (checksum >> 8) & 0xff;
	packet[37] = (checksum & 0x00ff); 

	/* finish IP packet */
	/* TTL of 64 */
	packet[8] = 64;
	/* protocol is TCP */
	packet[9] = 6;
	/* zero out checksum */
	packet[10] = 0;
	packet[11] = 0;
	/* source IP */
	packet[12] = src[0];
	packet[13] = src[1];
	packet[14] = src[2];
	packet[15] = src[3];
	/* destination IP */
	packet[16] = dst[0];
	packet[17] = dst[1];
	packet[18] = dst[2];
	packet[19] = dst[3];
	/* compute IP checksum (with checksum field = 0) */
	checksum = slip_sum(packet, 20);
	packet[10] = (checksum >> 8) & 0xff;
	packet[11] = (checksum & 0x00ff); 

	return size;
}
