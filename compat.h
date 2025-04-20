/* Compatibility shim for BASS
 * Copyright (C)2025, Cameron Kaiser. All rights reserved.
 * oldvcr.blogspot.com
 * BSD-2 clause
 *
 * This is a compatibility file to include what your OS needs, and set any
 * relevant types, especially on very old Unices or non-POSIXy operating
 * systems. MAIN, in particular, refers to how main() should be declared, and
 * the rest should be self-explanatory from their standard values.
 *
 * Only this file and slip.c should contain anything system-dependent
 * (ignoring time-related features of ntp.c).
 */

#if __GNUC__
/* mostly intended for testing on Linux or modern BSDs */
#define IS_POSIX	1
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#define SCH	signed char
#define B16	int16_t
#define B32	int32_t
#define	MAIN	int
#define OPEN_RW	O_RDWR
#else
/* assume Venix-11 or PRO/VENIX */
/* #undef IS_POSIX */
#if VENIX
#include <stdio.h>

#define SCH	char
#define B16	int
#define B32	long
#define MAIN	/* nothing */
#define	OPEN_RW	2

#else
you_should_probably_define_something_here;
#endif
#endif
