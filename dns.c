/* DNS helper for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This is a simple DNS helper that, given a C-string with a name to resolve,
 * your IP and an IP of a directly reachable recursive DNS server, returns the
 * IPv4 address (or an error code). It contains one function,
 * dns_dissolve().
 */

#include "compat.h"
#include "dns.h"
#include "slip.h"

/* add some paddin' */
#define PACKET_SIZE 640

/* returns number of answers, or 0 if failed/NXDOMAIN */
int dns_dissolve(name, src, dst, answer)
SCH *name; /* C-string of name to resolve */
SCH *src; /* our IPv4 address */
SCH *dst; /* IPv4 of server (must be able to handle recursive queries) */
SCH *answer; /* where we put the response, or an error code */
{
	B16 size, oldsize;
	/* RFC 6864 indicates that pretty much nothing relies on the
         * uniqueness of the IPv4 ID field anymore. */
	B16 checksum;
	int j, k, count, last, answers, type, class;
	SCH *i;
	SCH *packet;
	SCH trans_l, sport_l;
	SCH trans_h, sport_h;

	/* ass-U-me SLIP has been initialized */

	/* we clear the packet manually anyway, so don't bother with calloc */
	packet = malloc(PACKET_SIZE); /* maximum size for UDP DNS */
	if (!packet) {
		answer[0] = DNS_NOMEM;
		return 0;
	}
	slip_splat(packet, PACKET_SIZE);

	/***** IP header *****/
	/* version and length of IP header */
	packet[0] = 0x45;	/* IPv4, 5 32-bit ints == 20 bytes */

	/* TOS as DSCP and ECN: just use zero */
	packet[1] = 0x00;

	/* length of complete packet and payload, big endian */
	size = 20 + /* IP header */
		8 + /* UDP header */
		2 + /* DNS transaction ID */
		2 + /* DNS flags */
		8 + /* one question, 0 answer/authority/add'l RRs */
	strlen(name) + 2 + /* length of name plus initial byte and null */
		4; /* type A, class IN */
	/* is redonkulous? is redonkulous. you try again. */
	if (size > 511) {
		answer[0] = DNS_BIG_QUESTION;
		free(packet);
		return 0;
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

	/***** UDP pseudo-header *****/
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
	/* protocol, always 17 for UDP */
	packet[17] = 17;
	/* length,  minus IP header */
	packet[18] = ((size - 20) >> 8) & 0xff;
	packet[19] = ((size - 20) & 0x00ff);

	/***** UDP payload *****/
	/* source port. don't care, but make sure it matches */
	sport_h = rand() & 0xff;
	packet[20] = sport_h;
	sport_l = rand() & 0xff;
	packet[21] = sport_l;

	/* destination port, big endian */
	packet[22] = 0;
	packet[23] = 53;

	/* length again, minus IP header */
	packet[24] = ((size - 20) >> 8) & 0xff;
	packet[25] = ((size - 20) & 0x00ff);

	/* we'll come back to the checksum at the end */

	/***** DNS payload *****/
	/* transaction ID (random, but we check it) */
	trans_h = rand() & 0xff;
	packet[28] = trans_h;
	trans_l = rand() & 0xff;
	packet[29] = trans_l;

	/* flags 0x100, standard query, request recursion */
	packet[30] = 0x01;
	packet[31] = 0x00;

	/* one question */
	packet[32] = 0;
	packet[33] = 1;
	/* no answer RRs, no authority RRs, no additional RRs */
	packet[34] = 0;
	packet[35] = 0;
	packet[36] = 0;
	packet[37] = 0;
	packet[38] = 0;
	packet[39] = 0;

	/* append question */
	count = 0;
	last = 40;
	j = 41;
	for(i=name; *i; i++) {
		if (*i == '.') {
			packet[last] = count;
			count = 0;
			last = j++;
			continue;
		}
		packet[j++] = *i;
		count++;
	}
	packet[last] = count;
	packet[j++] = 0;

	/* append type A */
	packet[j++] = 0;
	packet[j++] = 1;
	/* append class IN */
	packet[j++] = 0;
	packet[j++] = 1;

	/* oops, assertion failed */
	if (j != size) {
		answer[0] = DNS_QUESTION_ERROR;
		free(packet);
		return 0;
	}

	/* compute UDP checksum (with checksum field = 0) */
	/* including pseudo header */
	/* pad null in checksum if not even 16-bit boundary */
	if (size & 1) {
		/* add null, incorporate into checksum, keep size */
		packet[j++] = 0;
		checksum = slip_sum(packet + 8, size - 7);
	} else {
		checksum = slip_sum(packet + 8, size - 8);
	}
	packet[26] = (checksum >> 8) & 0xff;
	packet[27] = (checksum & 0x00ff); 

	/***** finish IP packet ****/
	/* TTL of 64 */
	packet[8] = 64;
	
	/* protocol is UDP */
	packet[9] = 17;

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
	if(!slip_ship(packet, size)) {
		answer[0] = DNS_SLIP_ERROR;
		free(packet);
		return 0;
	}
	oldsize = size;

	for(;;) {
		size = slip_slurp(packet, PACKET_SIZE);
		if (!size) { /* something is wrong */
			answer[0] = DNS_SLIP_ERROR;
			free(packet);
			return 0;
		}

		j = packet[9]; /* hold for a moment */

		/* verify its checksum by reconstructing the pseudo-header */
		/* source IP */
		packet[8] = packet[12];
		packet[9] = packet[13];
		packet[10] = packet[14];
		packet[11] = packet[15];

		/* destination IP */
		packet[12] = packet[16];
		packet[13] = packet[17];
		packet[14] = packet[18];
		packet[15] = packet[19];

		/* zero, UDP, packet length */
		packet[16] = 0;
		packet[17] = 17;
		packet[18] = packet[24];
		packet[19] = packet[25];

		/* pad the packet to an even 16-bits per RFC 768 */
		if (size & 1) {
			/* add a null, incorporate null into checksum */
			packet[size] = 0;
			checksum = slip_sum(packet + 8, size - 7);
		} else {
			checksum = slip_sum(packet + 8, size - 8);
		}
		if (checksum) { /* RFC 1071 */
			answer[0] = DNS_BAD_ANSWER;
			free(packet);
			return 0;
			/* we don't wait again, the packet was mangled but
				because it's UDP it will not be re-sent.
				see if the caller wants to try again. */
		}

		/* fast kickouts */
		/* reject non-UDP */
		if (j != 17)
			continue;
		/* reject non-DNS replies */
		if (!(packet[30] & 128))
			continue;
		/* reject replies that aren't to our pseudoport */
		if (packet[22] != sport_h || packet[23] != sport_l)
			continue;
		/* reject replies that aren't to our query */
		if ((packet[28] != trans_h) || (packet[29] != trans_l))
			continue;

		/* we have a packet that purports to be our reply */
		break;
	}

	/***** process the reply *****/

	/* truncation: packet[30] & 2 */

	answers = (packet[34] << 8) + packet[35];
	/* the reply follows the question, so start from that offset */
#if DEBUG
for(j=0;j<size;j++) { if(j>=oldsize)
	fprintf(stderr, "/%02x ", (unsigned int)(packet[j] & 0xff));
	else fprintf(stderr, " %02x ", (unsigned int)(packet[j] & 0xff)); } 
fprintf(stderr, "\n");
#endif
	/* scan ahead until we get to the first record */
	for(j=oldsize;j<size;j++) {
		k = packet[j] & 0xff;
		if (k == 192) break;
	}
	if (j == size) {
		answer[0] = DNS_NO_ANSWERS;
		free(packet);
		return 0;
	}
	for(;j<size;answers--) {
		k = packet[j] & 0xff;
		if (!answers) {
			answer[0] = DNS_NO_ANSWERS;
			free(packet);
			return 0; /* we don't use the other sections */
		}
		k = packet[j] & 0xff;
		if (k != 192) {
			answer[0] = DNS_ANSWER_ERROR;
			free(packet);
			return 0; /* this isn't a DNS answer section */
		}
		type = packet[j+3] & 0xff;
		type += ((packet[j+2] & 0xff) << 8);
		class = packet[j+5] & 0xff;
		class += ((packet[j+4] & 0xff) << 8);
		/* TTL ignored in this implementation */
		count = packet[j+11] & 0xff;
		count += ((packet[j+10] & 0xff) << 8);
		if (type != 1 || class != 1 || count != 4) {
			/* not A, not IN, not IPv4 */
			j += count + 12; /* skip the header too */
			continue;
		}
		/* if there are multiple answers (there can be), we simply
			return the first one. */
		answer[0] = packet[j+12];
		answer[1] = packet[j+13];
		answer[2] = packet[j+14];
		answer[3] = packet[j+15];
#if DEBUG
fprintf(stderr, "%d.%d.%d.%d\n", (unsigned int)(answer[0] & 0xff),
	(unsigned int)(answer[1] & 0xff),
	(unsigned int)(answer[2] & 0xff),
	(unsigned int)(answer[3] & 0xff));
#endif
		free(packet);
		return answers; /* alternatives may exist */
	}

	/* there are no answers, only questions */
	answer[0] = DNS_NO_ANSWERS;
	free(packet);
	return 0;
}
