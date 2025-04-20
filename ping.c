/* Simple ping for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This pings the remote server. If you are using Slirp, you can probably
 * only reliably ping 10.0.2.2, which is defined as the host you are
 * immediately connected to; there is no route back for ICMP packets to
 * servers beyond the simulated Slirp network. If you are directly attached
 * as a true interface, you may be able to get other hops this way.
 *
 * DNS is intentionally not supported to have as few points of failure as
 * possible (if this works, then the problem is higher up).
 */

#include "compat.h"
#include "slip.h"

MAIN
main(argc, argv)
int argc;
char **argv;
{
	int i;
	B16 size;
	/* RFC 6864 indicates that pretty much nothing relies on the
         * uniqueness of the IPv4 ID field anymore. */
	B16 counter;
	B16 checksum;
	SCH *packet;

	if (argc != 9) {
		fprintf(stderr, "usage: %s so ur ce ip re mo te ip\n", argv[0]);
		exit(1);
	}

	/* we clear the packet manually anyway, so don't bother with calloc */
	packet = malloc(1536);
	if (!packet) {
		perror("malloc");
		exit(2);
	}

	if (!slip_setup()) {
		perror("SLIP failure");
		free(packet);
		exit(3);
	}

	/* ping loop starts here */
	counter = 1;
	size = 84; /* the packets we send are always this size */
	for(;;) {
		/* erase the packet */
		slip_splat(packet, size);

		/***** IP header *****/
		/* version and length of IP header */
		packet[0] = 0x45;	/* IPv4, 5 32-bit ints == 20 bytes */

		/* TOS as DSCP and ECN: internetwork control, no ECN */
		packet[1] = 0x00;

		/* length of complete packet and payload, big endian */
		packet[2] = (size >> 8) & 0xff;
		packet[3] = (size & 0x00ff);

		/* identification, big endian (see above) */
		packet[4] = rand() & 0xff;
		packet[5] = rand() & 0xff;

		/* fragmentation: none, not allowed */
		packet[6] = 0;
		packet[7] = 0;

		/* TTL of 64 */
		packet[8] = 64;
	
		/* protocol is ICMP */
		packet[9] = 1;

		/* source IP */
		packet[12] = atoi(argv[1]);
		packet[13] = atoi(argv[2]);
		packet[14] = atoi(argv[3]);
		packet[15] = atoi(argv[4]);

		/* destination IP */
		packet[16] = atoi(argv[5]);
		packet[17] = atoi(argv[6]);
		packet[18] = atoi(argv[7]);
		packet[19] = atoi(argv[8]);

		/* compute IP checksum (with checksum field = 0) */
		checksum = slip_sum(packet, 20);
		packet[10] = (checksum >> 8) & 0xff;
		packet[11] = (checksum & 0x00ff); 

		/***** ICMP payload *****/
		packet[20] = 0x08; /* ICMP echo */
		packet[21] = 0x00; /* ICMP code */
		/* opaque identifier */
		packet[24] = 0xe6;
		packet[25] = 0xc4;
		/* sequence number */
		packet[26] = (counter >> 8) & 0xff;
		packet[27] = (counter & 0x00ff);
		/* timestamp as uint64_t, currently a dummy value */
		packet[28] = 0x67;
		packet[29] = 0xd7;
		packet[30] = 0x65;
		packet[31] = 0x97;
		packet[32] = 0x00;
		packet[33] = 0x06;
		packet[34] = 0x7e;
		packet[35] = 0x42;

		/* fill remainder of packet */
		for(i=36; i<84; i++)
			packet[i] = i-28;

		/* compute ICMP checksum (with checksum field = 0) */
		checksum = slip_sum((packet + 20), 64);
		packet[22] = (checksum >> 8) & 0xff;
		packet[23] = (checksum & 0x00ff); 

		if(!slip_ship(packet, size)) {
			perror("SLIP failure");
			slip_stop();
			free(packet);
			exit(3);
		}

		for (;;) {
			size = slip_slurp(packet, 1536);
			/* reject non-ICMP */
			if (packet[9] != 1) continue;
			break;
		}
		/* check for mangled packets */
		/* compute ICMP checksum (IP was already checked) */
		checksum = slip_sum((packet + 20), size - 20);
		if (checksum) {
			fprintf(stdout, "mangled reply, retrying\n");
		} else {
			fprintf(stdout,
				"reply from %d.%d.%d.%d (packet %02x%02x)\n",
				(unsigned int)packet[12],
				(unsigned int)packet[13],
				(unsigned int)packet[14],
				(unsigned int)packet[15],
				(unsigned int)packet[26],
				(unsigned int)packet[27]);
		}
		sleep(1);
		counter++;
	}

	slip_stop();
	free(packet);
	exit(0);
}
