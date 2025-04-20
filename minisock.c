/* Simple TCP client for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * A simple TCP client that accepts a destination and a selection of strings
 * to send (which can be nothing, optionally separated or not by CR/LF), and
 * then returns the result. Suitable for HTTP/1.x, Gopher, Finger, Whois and
 * other such simplistic protocols.
 */

#include "compat.h"
#include "slip.h"
#include "dns.h"
#include "tcp.h"

SCH src[4] = { 0, 0, 0, 0};
SCH dst[4] = { 0, 0, 0, 0};
SCH seqno[4] = { 0, 0, 0, 0};
SCH oldseqno[4] = { 0, 0, 0, 0};
SCH ackno[4] = { 0, 0, 0, 0};

MAIN
main(argc, argv)
int argc;
char **argv;
{
	B16 checksum;
	int j, port, size, rsize, offs, base;
	SCH sport_h, sport_l, err, got, acked, crlf, dns;
	SCH *packet, *reply, *string;

	if (argc == 1) {
		fprintf(stderr, "usage: %s [-in] so ur ce ip se rv er ip [servername] port [string] [string] ...\n", argv[0]);
		exit(1);
	}
	dns = 1;
	crlf = 1;
	base = 1;
	acked = 0;
	if (argv[1][0] == '-') {
		base = 2;
		if (strlen(argv[1]) == 1) {
			fprintf(stderr, "no options specified\n");
			exit(1);
		}
		for(j=1;j<strlen(argv[1]);j++) {
			if (argv[1][j] == 'i') {
				dns = 0;
			} else if (argv[1][j] == 'n') {
				crlf = 0;
			} else {
				fprintf(stderr, "unknown option -%c\n",
					argv[1][j]);
				exit(1);
			}
		}
	}
	if (dns && argc < (base + 10)) {
		fprintf(stderr, "usage: %s so ur ce ip se rv er ip servername port [string] [string] ...\n", argv[0]);
		exit(1);
	}
	if (!dns && argc < (base + 9)) {
		fprintf(stderr, "usage: %s -n so ur ce ip se rv er ip port [string] [string] ...\n", argv[0]);
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

	/* save hostname */
	if (dns)
		dns = base++;

	port = atoi(argv[base++]);
	if (!port || port > 65535) {
		fprintf(stderr, "illegal port\n");
		exit(1);
	}

	/* gather what we're transmitting */
	string = malloc(MSS_WINDOW);
	if (!string) {
		perror("malloc");
		exit(2);
	}
	if (base == argc) {
		/* nothing to send */
		acked = 1;
	} else {
		acked = 0;
		/* any strings to send are now in argv[base] */
		/* check length */
		for(j=base;j<argc;j++) {
			size += strlen(argv[j]) + crlf + crlf;
		}
		/* XXX: make this bigger for sends in the future */
		if (size >= MSS_WINDOW) {
			fprintf(stderr, "limited to %d characters\n",
				MSS_WINDOW);
			exit(1);
		}
		/* construct full string to transmit */
		string[0] = 0;
		for(j=base;j<argc;j++) {
			strcat(string, argv[j]);
			if (crlf)
				strcat(string, "\r\n");
		}
	}

	reply = malloc(PACKET_SIZE);
	if (!reply) {
		perror("malloc");
		free(string);
		exit(2);
	}
	packet = malloc(PACKET_SIZE);
	if (!packet) {
		perror("malloc");
		free(reply);
		free(string);
		exit(2);
	}
	if (!slip_setup()) {
		perror("SLIP failure");
		free(packet);
		free(reply);
		free(string);
		exit(3);
	}

	/* resolve name now, if given */
	if (dns) {
		got = 0;
		for(j=0;j<3;j++) {
			/* use seqno temporarily as storage for IP answer */
			got = dns_dissolve(argv[dns], src, dst, seqno);
			if (got) break;
		}
		if (!got) {
			fprintf(stderr, "couldn't resolve %s\n", argv[dns]);
			free(packet);
			free(reply);
			free(string);
			slip_stop();
			exit(5);
		}
		dst[0] = seqno[0];
		dst[1] = seqno[1];
		dst[2] = seqno[2];
		dst[3] = seqno[3];
	}

	/***** TCP three-way handshake (ewww) *****/

	/* SYN phase */
	/* create random source port # */
	sport_h = rand() & 0xff;
	sport_l = rand() & 0xff;
	/* create random sequence number */
	seqno[0] = rand() & 0xff;
	seqno[1] = rand() & 0xff;
	seqno[2] = rand() & 0xff;
	seqno[3] = rand() & 0xff;
	/* zero out acknowledgement number */
	ackno[0] = 0;
	ackno[1] = 0;
	ackno[2] = 0;
	ackno[3] = 0;
	/* create SYN */
	size = tcp_template(packet, src, dst, port, sport_h, sport_l,
		2, seqno, ackno);
	/* wait for SYN+ACK, bump seqno, get ackno */
	got = tcp_twiddle(packet, size, (2 | 16), seqno, ackno, 1, &err);
	if (!got) {
		if (err == TCP_NOMEM) {
			fprintf(stderr, "out of memory\n");
		} else if (err == TCP_SLIP_ERROR) {
			fprintf(stderr, "transmission failed\n");
		} else {
			fprintf(stderr, "unexpected error %d\n", err);
		}
		free(packet);
		free(reply);
		free(string);
		slip_stop();
		exit(3);
	}
	if (got & 4) { /* RST => connection refused */
		fprintf(stderr, "connection refused\n");
		free(packet);
		free(reply);
		free(string);
		slip_stop();
		exit(4);
	}
#if DEBUG
fprintf(stderr, "seqno: us %02x%02x%02x%02x \n",
	(unsigned int)seqno[0] & 0xff,
	(unsigned int)seqno[1] & 0xff,
	(unsigned int)seqno[2] & 0xff,
	(unsigned int)seqno[3] & 0xff);
#endif
	/* bump ackno */
	tcp_total32(ackno, 1);
	/* use helper method to create ACK packet */
	size = tcp_template(packet, src, dst, port, sport_h, sport_l,
		16, seqno, ackno);
	if (!slip_ship(packet, size)) {
		perror("SLIP transmission failed");
		free(packet);
		free(reply);
		free(string);
		slip_stop();
		exit(3);
	}

	/***** send and receive phase *****/

	/* create packet to transmit, if one was specified */
	/* currently this must fit into our payload */
	if (!acked) {
		oldseqno[0] = seqno[0];
		oldseqno[1] = seqno[1];
		oldseqno[2] = seqno[2];
		oldseqno[3] = seqno[3];
		size = tcp_transmittal(packet, src, dst, port,
			sport_h, sport_l,
			seqno, ackno, string);
		if (!size) {
			fprintf(stderr, "out of memory\n");
			free(packet);
			free(reply);
			free(string);
			slip_stop();
			exit(2);
		}
		/* pre-compute expected value */
		tcp_total32(seqno, strlen(string));
	} /* otherwise pretend we sent "something" */

	for(;;) {
		/* if not already acked, send packet */
		if (!acked) {
			j = slip_ship(packet, size);
			if (!j) {
				perror("SLIP transmission failure");
				free(packet);
				free(reply);
				free(string);
				slip_stop();
				exit(3);
			}
		}
		rsize = slip_slurp(reply, PACKET_SIZE);
		if (!rsize) {
			perror("SLIP receive failure");
			free(packet);
			free(reply);
			free(string);
			slip_stop();
			exit(3);
		}

		/* verify its checksum by reconstructing the pseudo-header */
		j = reply[9]; /* hold temporarily */
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
		/* pad null in checksum if not even 16-bit boundary */
		if (rsize & 1) {
			reply[rsize] = 0;
			checksum = slip_sum(reply + 8, rsize - 7);
		} else {
			checksum = slip_sum(reply + 8, rsize - 8);
		}
		if (checksum) { /* RFC 1071 */
			continue;
		}

		/* reject non-TCP */
		if (j != 6) continue;
		/* reject anything not to our port */
		if (reply[22] != sport_h || reply[23] != sport_l)
			continue;

		/* check flags */
		if (reply[33] & 4) /* RST */
			break;

		if ((reply[33] & 16) || (reply[33] & 1)) { /* ACK or FIN */
			/* they sent data first if ackno == old seqno */
			if (
				reply[28] == oldseqno[0] &&
				reply[29] == oldseqno[1] &&
				reply[30] == oldseqno[2] &&
				reply[31] == oldseqno[3]
			) {
				/* fall through */
			} else {
				if (!acked) {
					/* make sure ackno == our seqno */
					if (
						reply[28] == seqno[0] &&
						reply[29] == seqno[1] &&
						reply[30] == seqno[2] &&
						reply[31] == seqno[3]
					) acked = 1;
				}
			}
		}
#if DEBUG
fprintf(stderr, "seqno: them %02x%02x%02x%02x | us %02x%02x%02x%02x \n",
	(unsigned int)reply[28] & 0xff,
	(unsigned int)reply[29] & 0xff,
	(unsigned int)reply[30] & 0xff,
	(unsigned int)reply[31] & 0xff,
	(unsigned int)seqno[0] & 0xff,
	(unsigned int)seqno[1] & 0xff,
	(unsigned int)seqno[2] & 0xff,
	(unsigned int)seqno[3] & 0xff);
#endif

		/***** receive data *****/
		offs = reply[32] >> 2;
		offs += 20; /* skip IP header */
		if (offs >= rsize) {
			/* no data */
			/* breakout if FIN or SYN */
			if (reply[33] & 1) break;
			if (reply[33] & 2) break;
			/* else wait for more */
			continue;
		}

		/* check that the sequence number is what we're expecting */
		if (
			reply[24] == ackno[0] &&
			reply[25] == ackno[1] &&
			reply[26] == ackno[2] &&
			reply[27] == ackno[3]
		) {
#if DEBUG
fprintf(stderr, "ackno: them %02x%02x%02x%02x | us %02x%02x%02x%02x \n",
	(unsigned int)reply[24] & 0xff,
	(unsigned int)reply[25] & 0xff,
	(unsigned int)reply[26] & 0xff,
	(unsigned int)reply[27] & 0xff,
	(unsigned int)ackno[0] & 0xff,
	(unsigned int)ackno[1] & 0xff,
	(unsigned int)ackno[2] & 0xff,
	(unsigned int)ackno[3] & 0xff);
#endif
			/* print data received */
			/* (note that technically we should wait for a PSH) */
			for(j=offs;j<rsize;j++) {
				fprintf(stdout, "%c", reply[j]);
			}
			/* rev ackno by the length to indicate acceptance */
			tcp_total32(ackno, rsize - offs);
#if DEBUG
fprintf(stderr, "ackno: them %02x%02x%02x%02x | us %02x%02x%02x%02x \n",
	(unsigned int)reply[24] & 0xff,
	(unsigned int)reply[25] & 0xff,
	(unsigned int)reply[26] & 0xff,
	(unsigned int)reply[27] & 0xff,
	(unsigned int)ackno[0] & 0xff,
	(unsigned int)ackno[1] & 0xff,
	(unsigned int)ackno[2] & 0xff,
	(unsigned int)ackno[3] & 0xff);
#endif
		}

		/* if FIN, break out here */
		if (reply[33] & 1) break;

		/* create an ACK */
		size = tcp_template(packet, src, dst, port, sport_h, sport_l,
			16, seqno, ackno);
		/* send it */
		if (!slip_ship(packet, size)) {
			perror("SLIP transmission error");
			free(packet);
			free(reply);
			free(string);
			exit(3);
		}
		/* our packet needs to be regenerated with new ackno */
		if (!acked) {
			size = tcp_transmittal(packet, src, dst, port,
				sport_h, sport_l,
				seqno, ackno, string);
		}
		/* loop and resend */
	}

	/***** connection is terminating *****/
	if (reply[33] & 4) { /* terminated on RST, don't send anything else */
		fprintf(stderr, "connection reset\n");
		free(packet);
		free(reply);
		free(string);
		exit(3);
	}
	if (reply[33] & 2) { /* terminated on SYN?!, send a RST */
		size = tcp_template(packet, src, dst, port, sport_h, sport_l,
			4, seqno, ackno);
		/* send it, but just suppress the error if it fails */
		slip_ship(packet, size);
		free(packet);
		free(reply);
		free(string);
		/* call it a normal termination, I guess */
		exit(0);
	}

#if DEBUG
fprintf(stderr, "seqno! them %02x%02x%02x%02x | us %02x%02x%02x%02x \n",
	(unsigned int)reply[28] & 0xff,
	(unsigned int)reply[29] & 0xff,
	(unsigned int)reply[30] & 0xff,
	(unsigned int)reply[31] & 0xff,
	(unsigned int)seqno[0] & 0xff,
	(unsigned int)seqno[1] & 0xff,
	(unsigned int)seqno[2] & 0xff,
	(unsigned int)seqno[3] & 0xff);
fprintf(stderr, "ackno! them %02x%02x%02x%02x | us %02x%02x%02x%02x \n",
	(unsigned int)reply[24] & 0xff,
	(unsigned int)reply[25] & 0xff,
	(unsigned int)reply[26] & 0xff,
	(unsigned int)reply[27] & 0xff,
	(unsigned int)ackno[0] & 0xff,
	(unsigned int)ackno[1] & 0xff,
	(unsigned int)ackno[2] & 0xff,
	(unsigned int)ackno[3] & 0xff);
#endif

	/***** TCP teardown *****/
	/* send final FIN+ACK */
	size = tcp_template(packet, src, dst, port, sport_h, sport_l,
		(1 | 16), seqno, ackno);
	/* wait for ACK, bump seqno, get ackno */
	got = tcp_twiddle(packet, size, (1 | 16), seqno, ackno, 1, &err);
	/* ignore any errors, we're terminating anyway */
	if (got) {
		/* send my FIN */
		size = tcp_template(packet, src, dst, port, sport_h, sport_l,
			1, seqno, ackno);
		/* wait for FIN-ACK, don't! bump seqno, get ackno */
		got = tcp_twiddle(packet, size, (1 | 16), seqno, ackno, 0, &err);
		if (got) {
			/* bump ackno, send my ACK */
			tcp_total32(ackno, 1);
			size = tcp_template(packet, src, dst, port, sport_h,
				sport_l, 16, seqno, ackno);
			got = slip_ship(packet, size);
		}
	}
	free(packet);
	free(reply);
	free(string);
	slip_stop();
	exit((got) ? 0 : 3);
}

