/* Simple NTP client for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * Asks an NTP server for the current time with a simple v3 query and
 * displays it.
 *
 * XXX: The end section which processes the time is probably system-dependent,
 * though it oughtn't be.
 */

#include "compat.h"
#include "dns.h"
#include "slip.h"

/* NTP is up to 544 bytes + 20 IP + 8 UDP + fudgy fudge factor */
#define PACKET_SIZE 640

SCH src[4] = {0, 0, 0, 0};
SCH dst[4] = {0, 0, 0, 0};
SCH answer[4] = {0, 0, 0, 0};

MAIN
main(argc, argv)
int argc;
char **argv;
{
	/* RFC 6864 indicates that pretty much nothing relies on the
         * uniqueness of the IPv4 ID field anymore. */
	B16 checksum;
	B32 ntime;
	B32 epoch = 2208988800;
	int j, size, base;
	SCH *packet;
	SCH dns, sport_h, sport_l;

	if (argc == 1) {
		fprintf(stderr, "usage: %s [-i] so ur ce ip se rv er ip [hostname]\n", argv[0]);
		exit(1);
	}
	dns = 1;
	base = 1;
	if (argv[1][0] == '-') {
		base = 2;
		if (argv[1][1] == 'i') {
			dns = 0;
		} else {
			fprintf(stderr, "unknown option %c\n", argv[1][1]);
			exit(1);
		}
	}	 
	if (argc < (base + 8 + dns)) {
		fprintf(stderr, "usage: %s [-i] so ur ce ip se rv er ip [hostname]\n", argv[0]);
		exit(1);
	}

	src[0] = atoi(argv[base++]);
	src[1] = atoi(argv[base++]);
	src[2] = atoi(argv[base++]);
	src[3] = atoi(argv[base++]);

	dst[0] = atoi(argv[base++]);
	dst[1] = atoi(argv[base++]);
	dst[2] = atoi(argv[base++]);
	dst[3] = atoi(argv[base++]);

	/* we clear the packet manually anyway, so don't bother with calloc */
	packet = malloc(PACKET_SIZE);
	if (!packet) {
		perror("malloc");
		exit(2);
	}
	slip_splat(packet, PACKET_SIZE);
	if (!slip_setup()) {
		perror("SLIP failure");
		free(packet);
		exit(4);
	}

	if (dns) {
		for(j=0;j<3;j++) {
			size = dns_dissolve(argv[base], src, dst, answer);
			if (size) break;
		}
		if (!size) {
			fprintf(stderr, "could not resolve hostname\n");
			free(packet);
			slip_stop();
			exit(3);
		}
		dst[0] = answer[0];
		dst[1] = answer[1];
		dst[2] = answer[2];
		dst[3] = answer[3];
	}

	/***** IP header *****/
	/* version and length of IP header */
	packet[0] = 0x45;	/* IPv4, 5 32-bit ints == 20 bytes */

	/* TOS as DSCP and ECN: just use zero */
	packet[1] = 0x00;

	/* length of complete packet and payload, big endian */
	size = 20 + /* IP header */
		8 + /* UDP header */
		48; /* size of NTP request */
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
	/* source port. don't care, but check it matches */
	sport_h = rand() & 0xff;
	packet[20] = sport_h;
	sport_l = rand() & 0xff;
	packet[21] = sport_l;

	/* destination port, big endian */
	packet[22] = 0;
	packet[23] = 123;

	/* length again, minus IP header */
	packet[24] = ((size - 20) >> 8) & 0xff;
	packet[25] = ((size - 20) & 0x00ff);

	/* we'll come back to the checksum at the end */

	/***** NTP payload *****/
	packet[28] = 0x1b; /* version number (v3) + client query */
	/* remainder is zero and is already clear */

	/* compute UDP checksum (with checksum field = 0) */
	/* including pseudo header */
	checksum = slip_sum(packet + 8, size - 8);
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
		perror("SLIP failure");
		free(packet);
		exit(4);
	}

	for(;;) {
		size = slip_slurp(packet, PACKET_SIZE);
		if (!size) { /* something is wrong */
			perror("SLIP failure");
			free(packet);
			exit(4);
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

		/* packet is always even sized */
		if (size & 1) {
			fprintf(stderr, "corrupt response from server\n");
			free(packet);
			exit(5);
			/* we don't wait again, the packet was mangled but
				because it's UDP it will not be re-sent. */
		}
		checksum = slip_sum(packet + 8, size - 8);
		if (checksum) { /* RFC 1071 */
			fprintf(stderr, "corrupt response from server\n");
			free(packet);
			exit(5);
			/* again, no way to recover */
		}
		if (size < (20+8+48)) {
			fprintf(stderr, "truncated response from server\n");
			free(packet);
			exit(5);
			/* again, no way to recover */
		}

		/* fast kickouts */
		/* reject non-UDP */
		if (j != 17)
			continue;
		/* reject replies that aren't to our pseudoport */
		if (packet[22] != sport_h || packet[23] != sport_l)
			continue;

		/* we have a packet that purports to be our reply */
		break;
	}

	/***** process the reply *****/
	fprintf(stdout, "stratum %d refid ", packet[29]);
	if (packet[29] == 1) {
		for(j=40;j<44;j++) {
			if (packet[j] < 32 || packet[j] > 127) break;
			fprintf(stdout, "%c", packet[j]);
		}
		fprintf(stdout, "\n");
	} else {
		fprintf(stdout, "%d.%d.%d.%d\n",
			(unsigned int)(packet[40] & 0xff),
			(unsigned int)(packet[41] & 0xff),
			(unsigned int)(packet[42] & 0xff),
			(unsigned int)(packet[43] & 0xff));
	}

	/***** SYSTEM DEPENDENT CODE! *****/
	/* this section would have made David L. Mills very unhappy */
	/* the reply is (at least) 12 32-bit big-endian ints */
	/* we want the count of seconds */
	/* build the value manually to avoid conversion problems */
	ntime = (packet[68] & 0xff);
	ntime <<= 8;
	ntime |= (packet[69] & 0xff);
	ntime <<=8;
	ntime |= (packet[70] & 0xff);
	ntime <<=8;
	ntime |= (packet[71] & 0xff);
#if IS_POSIX
	{
		time_t t = (time_t)ntime;
		t -= (time_t)epoch;
		fprintf(stdout, "%s\n", ctime(&t));
	}
#else
#if VENIX
#if DEBUG
	fprintf(stdout, "value: %lu\n", ntime);
#endif
#endif
	ntime -= epoch;
#if VENIX
#if DEBUG
	fprintf(stdout, "adjusted: %lu\n", ntime);
#endif
#endif
	fprintf(stdout, "%s\n", ctime(&ntime));
#endif
	slip_stop();
	free(packet);
	exit(0);
}
