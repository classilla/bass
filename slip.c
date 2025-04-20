/* SLIP driver for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This is the system-dependent SLIP driver for BASS. It expects to be
 * directly connected to its host using slattach or Slirp or similar. It
 * does not currently support CSLIP. It also contains utility functions
 * for clearing and checksumming packets.
 *
 * slip_setup() is called to initialize the connection.
 * slip_splat() clears a packet to zeroes. If you have memset() or bzero()
 * that can be faster than the manual approach here.
 * slip_sum() checksums a packet using the RFC algorithm. It can be used for
 * other protocols like UDP and TCP by adjusting the start and length, and
 * making any changes needed for those protocols' pseudoheaders. It returns
 * the checksum as a 16-bit int.
 * slip_slurp() waits for a complete packet and verifies length and checksum.
 * A packet returned from this function can be assumed to be valid. It returns
 * the number of bytes received.
 * slip_stop() halts the SLIP link.
 *
 * As written, this hardcodes paths and bitrates. You should modify it for
 * your local system. When compiling with gcc/clang, it will use /dev/ttyUSB0
 * at 4800bps. When compiled for Venix, it will use /dev/lp at 4800bps.
 *
 * Only this file and compat.h should contain anything system-dependent
 * (ignoring time-related features of ntp.c).
 */

#include "compat.h"
#include "slip.h"

/* #define USE_STDOUT	1 */
/* #define NO_ESCAPE	1 */
#if IS_POSIX
#define OUTPUT		"/dev/ttyUSB0"
#endif
#if VENIX
#include <sgtty.h>
#define OUTPUT	"/dev/lp"
#endif

#define	SLIP_END	0xc0
#define	SLIP_ESC	0xdb
/* SLIP_ESC_END */
#define	SLIP_NDE	0xdc
/* SLIP_ESC_ESC */
#define	SLIP_SCE	0xdd

/* 192, 219, 220, 221 or -64, -37, -36, -35 */

SCH slip_end[2] = { SLIP_ESC, SLIP_NDE };
SCH slip_esc[2] = { SLIP_ESC, SLIP_SCE };
SCH slip_done[1] = { SLIP_END };

int fd = -1;

int slip_setup()
{
#if USE_STDOUT
	srand(time(NULL));
	fd = 1;
#else
#if IS_POSIX
	srand(time(NULL));
	fd = open(OUTPUT, O_RDWR | O_NOCTTY | O_SYNC );
	if (fd < 0) {
		perror("slip_setup failed: open");
		return 0;
	} else {
		struct termios ttya;

		memset(&ttya, 0, sizeof(ttya));
		/* eat it! eat it raw! */
		ttya.c_cflag = (CS8 | CREAD | CLOCAL); /* 8N1 */
		ttya.c_cc[VTIME] = 0;
		ttya.c_cc[VMIN] = 1; /* intentional blocking read for testing */
		cfsetospeed(&ttya, B4800);
		cfsetispeed(&ttya, B4800);
		tcsetattr(fd, TCSANOW, &ttya);
		tcflush(fd, TCIOFLUSH);
	}
#else
	fd = open(OUTPUT, OPEN_RW);
	if (fd < 0) {
		perror("slip_setup failed: open");
		return 0;
	} else {
#if VENIX
		struct sgttyb ttybuf;
		long ltime;
		int itime;

		/* you can't just srand(time(NULL)) */
		time(&ltime);
		itime = ltime;
		srand(itime);

		ioctl(fd, TIOCGETP, &ttybuf);	
		/* paranoia */
		ttybuf.sg_ispeed = B4800;
		ttybuf.sg_ospeed = B4800;
		/* eat it! eat it raw! (see TTY(7)) */
		ttybuf.sg_flags = RAW;
		/* this autoflushes */
		ioctl(fd, TIOCSETP, &ttybuf);

		/* NB: a fashion of non-blocking I/O is available with */
		/* TIOCQCNT and sg_ispeed/sg_ospeed, but we don't use it */
#else
you_should_probably_define_something_here;
#endif
	}
#endif
#endif
	return 1;
}

int slip_splat(payload, size)
SCH *payload;
int size;
{
	int i;

	/* zero the buffer: don't assume we have memset or bzero */
	for(i=0; i<size; i++)
		payload[i] = 0;
	return size;
}

/* work around various compiler and signage bugs in old compilers */
B16 slip_sum(payload, size)
SCH *payload;
int size;
{
	B32 sum = 0;
	B32 j, k; /* used for intermediate values */
	B32 m = (B32)65535;
	int i = size;

	while(i > 1) {
		/* sum as big-endian shorts, though not required by RFC 1071 */
		/* keep everything long so we minimize conversion mismatches */
		j = *payload++;
		j &= 0xff;
		j <<= 8;
		k = *payload++;
		k &= 0xff;
		j |= k;
		sum += j;
		i -= 2;
	}

	/* add last byte, if not an even multiple of two */
	if (i > 0) {
		j = *payload;
		j &= 0xff;
		sum += j;
	}

	/* fold to 16 bits: remember, this might be signed */
	/* work around various 16-bit compiler bugs with 32-bit quantities */
	while (sum > m)
		sum = (sum & m) + ((sum >> 16) & m);

	sum = sum & m; /* paranoia */
	return sum ^ m;
}

/* blocking write */
int slip_ship(payload, size)
SCH *payload;
int size;
{
	int i, j;

	if (fd < 0)
		return 0;

	write(fd, &slip_done, 1);
	for(i=0;i<size;i++) {
		j = *payload & 0xff;
#if DEBUG
		fprintf(stderr, " %02x ", j);
#endif
#if NO_ESCAPE
		{
#else
		if (j == SLIP_END) {
			write(fd, &slip_end, 2);
		} else if (j == SLIP_ESC) {
			write(fd, &slip_esc, 2);
		} else {
#endif
			write(fd, payload, 1);
		}
		payload++;
	}
#if DEBUG
	fprintf(stderr, "\n");
#endif
	write(fd, &slip_done, 1);
	return 1;
}

/* blocking read */
int slip_slurp(payload, size)
SCH *payload;
int size;
{
	int i, j, newsize;
	SCH c, d;
	SCH *newp;

	if (fd < 0)
		return 0;
	if (!slip_splat(payload, size))
		return 0;

	/* keep reading until we get an IPv4 byte and a valid DSCP/ECN byte */
	/* this allows a modicum of proper framing, since it isn't guaranteed */
	/* that we'd get a SLIP_END/c0 as a lead byte */
	c = 0;
	d = 0;
	for(;;) {
		i = read(fd, &d, 1);
#if DEBUG
		/* these may or may not be castoffs */
		fprintf(stderr, ".%02x.", (unsigned int)(d & 0xff));
#endif
		if (c == 0x45) {
			/* XXX: others? */
			if (d == 0x00 || d == 0x08 || d == 0x10)
				break; /* valid */
		}
		c = d;
	}
#if DEBUG
	fprintf(stderr, "\n");
#endif
	payload[0] = 0x45;
	payload[1] = d;
	newp = payload + 1;
	/* keep reading until we get a SLIP END byte or run out of memory */
	for(newsize=1; newsize<size; newsize++) {
		i = read(fd, ++newp, 1);
		j = (*newp) & 0xff;
		if (j == SLIP_END) break; /* c0 */

		/* unescape escaped sequences */
		if (j == SLIP_ESC) {
			i = read(fd, &c, 1);
			j = c & 0xff;
			if (j == SLIP_SCE) {
				*newp = SLIP_ESC;
				continue;
			} else if (j == SLIP_NDE) {
				*newp = SLIP_END;
				continue;
			} else {
				/* likely not SLIP, abort */
#if DEBUG
				fprintf(stderr, "slip: nonsense ESC\n");
#endif
				return 0;
			}
		}			
	}
	newsize++;
#if DEBUG
	for (i=0;i<newsize;i++) { fprintf(stderr, "-%02x ",
		(unsigned int)(payload[i] & 0xff)); }
	fprintf(stderr, "\n");
#endif
	if (newsize >= size) { /* buffer full, likely not SLIP */
#if DEBUG
		fprintf(stderr, "slip: buffer oversize %d > %d\n", newsize, size);
#endif
		return 0;
	}

	/* validate the length and IP header checksum */
	i = payload[3] & 0xff;
	i += ((payload[2] & 0xff) << 8);
	if (i != newsize) { /* length is wrong */
#if DEBUG
		fprintf(stderr, "slip: length mismatch %d != %d\n", i, newsize);
#endif
		return 0;
	}
	i = slip_sum(payload, 20); /* including checksum */
	if (i) { /* see RFC 1071 */
#if DEBUG
		fprintf(stderr, "slip: corrupt IP header\n");
#endif
		return 0; 
	}
	/* caller is responsible for any checksums on the remainder */
	return newsize;
}

int slip_stop()
{
	close(fd); /* ignore return code */
	fd = -1;
	return 0;
}
