/* Basic DNS client for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This is a demonstration app for the DNS resolver that returns the IPv4
 * address of the requested hostname. The NTP and TCP clients embed the
 * resolver themselves.
 */

#include "compat.h"
#include "slip.h"
#include "dns.h"

SCH srcip[4] = { 10, 0, 2, 15 };
SCH dstip[4] = { 127, 0, 0, 53 };
SCH answer[4] = { 255, 255, 255, 255 };

MAIN
main(argc, argv)
int argc;
char **argv;
{
	int i, j;

	if (argc != 10) {
		fprintf(stderr, "usage: %s so ur ce ip re so lv er name\n",
			argv[0]);
		exit(1);
	}
	if (!slip_setup())
		exit(1);

	srcip[0] = atoi(argv[1]);
	srcip[1] = atoi(argv[2]);
	srcip[2] = atoi(argv[3]);
	srcip[3] = atoi(argv[4]);

	dstip[0] = atoi(argv[5]);
	dstip[1] = atoi(argv[6]);
	dstip[2] = atoi(argv[7]);
	dstip[3] = atoi(argv[8]);

	/* try a few times in case */
	for(i=0; i<3; i++) {
		j = dns_dissolve(argv[9], srcip, dstip, answer);
		if (j) {
			fprintf(stdout, "%d.%d.%d.%d\n",
				(unsigned int)(answer[0] & 0xff),
				(unsigned int)(answer[1] & 0xff),
				(unsigned int)(answer[2] & 0xff),
				(unsigned int)(answer[3] & 0xff));
			slip_stop();
			exit(0);
		}
		/* there were no answers, check code */
		if (answer[0] == DNS_SLIP_ERROR) {
			fprintf(stdout, "SLIP link failure, aborting\n");
			slip_stop();
			exit(2);
		}
		if (answer[0] == DNS_BIG_QUESTION) {
			fprintf(stdout, "cannot resolve hostname over UDP\n");
			slip_stop();
			exit(3);
		}
		if (answer[0] == DNS_QUESTION_ERROR ||
			answer[0] == DNS_ANSWER_ERROR) {
			fprintf(stdout, "internal DNS error, aborting\n");
			slip_stop();
			exit(4);
		}
		/* try again if no answers or a corrupt answer */
		if (answer[0] != DNS_NO_ANSWERS &&
			answer[0] != DNS_BAD_ANSWER) {
			fprintf(stdout, "unexpected error code %d\n",
				answer[0]);
			slip_stop();
			exit(5);
		}
		sleep(1);
	}

	fprintf(stdout, "could not resolve\n");
	slip_stop();
	exit(1);
}
