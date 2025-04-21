# Barely Adequate SLIP Stack (BASS)

[Another Old VCR Deviation from Decency!](https://oldvcr.blogspot.com/2025/04/lets-give-provenix-barely-adequate-pre.html)

Copyright &copy; 2025 Cameron Kaiser.  
All rights reserved.  
BSD license.

## What it is

BASS is a very tiny, barely useful client implementation of IPv4 over SLIP intended as a model for low-power, low-bandwidth computers, supporting TCP, UDP and ICMP. Although written in C, it can be built by very old compilers and only requires a 32-bit `long`, an `int` of at least 16 bits, and a generic `char` type which can be signed or unsigned. It assumes nothing about endianness and is adaptable even to 8-bit architectures. It makes minimal demands of the C standard library, requiring only `malloc`, `free`, `open`, `read` (which need not be non-blocking), `write`, `close`, `printf`, `fprintf`, `perror`, `strcat`, `strlen`, `rand`, `srand`, `sleep` and `exit`. All of these are relatively easy functions to implement or substitute for, making ports to bare metal and/or assembly language very feasible.

The default toolkit contains four clients: a `ping` tool (implements ICMP), an `nslookup` tool to query a provided DNS server (implements UDP and DNS), an `ntp` tool to query a provided NTPv3 clock source, and a `minisock` tool to send an optional set of strings to a server via TCP and read from the socket until it closes (implements TCP). This tool can be used to construct protocols like HTTP/1.x, Gopher, finger and Whois. All four tools talk over a single SLIP connection to a connected host. These tools create and send their own datagrams which are copiously commented in the source.

Two helper files are included, a simple DNS resolver and a low-level TCP toolkit which reduces the boilerplate to create and await datagrams. The SLIP driver also includes utility functions for clearing and checksumming packets. The checksum function can be used to checksum not only IP but also UDP and TCP if the appropriate pseudoheader is constructed and offset and length adjusted accordingly.

## What it isn't

BASS is explicitly designed around these assumptions:

  * Such systems will be acting as clients, not servers.
  * Network access is not concurrent (which is to say, one task at a time, one connection at a time).

Additionally, BASS does not implement timeouts, because it assumes no features to facilitate this on the part of the operating system, nor early aborts for TCP links, nor does it multiplex connections. It also does not support IPv6, largely because Slirp currently does not.

**Don't file issues for these deficiencies;** you may be eaten by a grue and/or subjected ineffectively to the Spanish Inquisition. If you need a more full-featured stack for small systems, especially if these systems need to act as servers, you might consider something like lwIP or Contiki.

## Out of the box

BASS was originally written for PRO/VENIX, a "true Unix" for the DEC Professional line of personal computers based on the 16-bit PDP-11 architecture. PRO/VENIX (hereafter Venix except as specified) was descended from Unix Version 7 initially and the final version from UNIX System V Release 2 (SVR2). It compiles without modifications on (at least) PRO/VENIX V2.0 and is fully tested on real Pro 380 hardware, and compiles on PRO/VENIX Rev. 2.0 (though additional testing is required). On PRO/VENIX systems the SLIP connection is made through the serial printer port `/dev/lp` using a BCC05 cable or compatible at 4800bps, which is the maximum speed. This keeps the main serial port available as a secondary login and terminal. BASS is built with `make -f Makefile.venix` (add `-DDEBUG` to the compiler options for debugging output).

BASS was prototyped on both macOS and Fedora Linux. Building on a modern OS can be useful for understanding what actually gets sent over the wire and also made testing changes faster. Your system should provide both BASS and a SLIP server it can connect to, which generally means two serial ports connected with a null modem. As configured the BASS clients will communicate via `/dev/ttyUSB0` at 4800bps; you would run the SLIP server at 4800bps on the other connected serial port, such as [Slirp-CK](https://github.com/classilla/slirp-ck). Since this build is more useful for debugging, the standard `Makefile` has `-DDEBUG` by default, which displays decoded and received traffic. It can be built on most modern operating systems with a simple `make`.

Once the SLIP server is listening on the other side, any of the included clients can be run directly; there is no special step for "bringing up" or "down" the interface. All of the clients require their own IPv4 address as their initial arguments (i.e., there is no analogue for `ip` or `ifconfig`). Note that address octets are separated by spaces, not dots (this is laziness turned into virtue as it doesn't require any special argument processing nor implementing an `inet_aton`).

### `ping`

`ping` sends ICMP echo requests to the specified IPv4 address. Whether it gets a reply is whether the reply can be routed back. With Slirp this is often not possible, and the only address that can be reliably pinged is 10.0.2.2, which is the Slirp internal address for the directly connected host. This is nevertheless enough to demonstrate the connection is live. Other SLIP connections may be routable back and more distant hosts could respond.

Usage: `./ping so ur ce ip re mo te ip`  
Example: `./ping 10 0 2 15 10 0 2 2`

### `nslookup`

`nslookup` queries the provided Domain Name System nameserver to resolve the requested name to an IPv4 address. The nameserver must be recursive and answer on UDP port 53. TCP DNS queries are not currently supported.

Usage: `./nslookup so ur ce ip re so lv er name`  
Example: `./nslookup 10 0 2 15 8 8 8 8 google.com`

### `ntp`

`ntp` queries the provided NTPv3-compatible server to obtain the current time. The second address provided is the nameserver to resolve the name of the NTP server. It adjusts the NTP epoch to the Unix epoch and displays the stratum, refid and time as received. It does not set the clock -- you get to do that. If you pass the `-i` option, then an IP address is accepted instead of a nameserver address and hostname.

Usage: `./ntp [-i] so ur ce ip se rv er ip [hostname]`  
Example: `./ntp 10 0 2 15 8 8 8 8 pool.ntp.org`

### `minisock`

`minisock` opens a TCP connection to the provided host and port. In addition to the usual self IP address and DNS server (or, if `-i` is passed, a bare IPv4 address) as parameters, plus the hostname/IP and port, it accepts a set of optional trailing strings. These strings are concatenated with CR-LF (unless `-n` is passed) up to the maximum length of the window, which out of the box is 256 bytes. When the connection is opened, the string buffer is transmitted if provided, after which `minisock` streams data from the connection to standard output until the remote side terminates.

This utility can be used to construct client queries compatible with HTTP/1.x, Gopher, finger, Whois and other similar protocols of the command-response variety.

Usage: `./minisock [-in] so ur ce ip se rv er ip [servername] port [string] [string] ...`  
Example (Gopher): `./minisock 10 0 2 15 8 8 8 8 gopher.floodgap.com 70 ""`  
Example (HTTP/1.x): `./minisock 10 0 2 15 8 8 8 8 www.floodgap.com 80 "GET / HTTP/1.0" "Host: www.floodgap.com" "Connection: close" ""`

## Writing your own clients

`slip.c`, `dns.c` and `tcp.c` along with their corresponding headers can be used in your own programs. All functions return zero for failure and non-zero for success. In the below, `SCH` refers to a `signed char` type, `B16` to an integer type of 16 bits, and `int` to any integer 16 bits or larger.

### `slip.c`

`int slip_setup();`  
Open the connection and do any preparation for network access (in this version, it also initializes the random number generator). You must call this function before calling `slip_ship` or `slip_slurp`, or calling any function that calls them.

`B16 slip_sum(SCH *payload, int size);`  
Provided a pointer to a datagram and a length, compute the IP checksum and return it. You are responsible for incorporating it into the datagram.

`int slip_ship(SCH *payload, int size);`  
Provided a pointer to a ready-to-send datagram and a length, send it over the wire, encoding it for SLIP.

`int slip_splat(SCH *payload, int size);`  
Provided a pointer to a datagram (or a newly allocated buffer) and a length, clear it to zero.

`int slip_slurp(SCH *payload, int size);`  
Provided a pointer to a buffer for a datagram and a maximum length, wait for a datagram to be received (possibly forever), check the IPv4 header for validity, and then place it into the buffer. If an invalid datagram or garbage is received, or the buffer will overflow, it will return zero. Otherwise, it returns the length of the new datagram, which is guaranteed to be valid at least for the IP portion.

`int slip_stop();`  
Closes the connection.

### `dns.c`

`int dns_dissolve(SCH *name, SCH *src, SCH *dst, SCH *answer);`  
Provided a pointer to a C string name, and four byte pointers for the self IPv4 address, the IPv4 address of the DNS server and the answer, attempt to resolve the name via the provided server over UDP and wait for a reply, possibly forever. If the return value is non-zero, the response was successful and the first answer is placed into `answer`. Return values greater than 1 indicate other answers are possible and you may or may not get them if you make the call again. If the return value is zero, the response was unsuccessful and `answer[0]` contains an error code (see `dns.h` for this list).

### `tcp.c`

`int tcp_total32(SCH *value, int inc);`  
Provided a pointer to a 32-bit big endian value and a 16-bit increment, increment the value by the increment. If the return value is zero, overflow occurred.

`int tcp_template(SCH *packet, SCH *src, SCH *dst, int port, SCH sport_h, SCH sport_l, SCH flags, SCH *seqno, SCH *ackno);`  
Provided a pointer to a buffer for a datagram, the self IPv4 address and the IPv4 address of the remote server, a TCP port number, two halves of a source port number, TCP flags, and pointers to 32-bit big endian values for the sequence number and acknowledgement number, construct a TCP control packet using these parameters and checksum both the TCP and IP portions, and place the ready-to-send datagram in the buffer. The buffer should be at least `PACKET_SIZE` bytes (see `tcp.h`). The size of the new datagram is returned.

`int tcp_transmittal(SCH *packet, SCH *src, SCH *dst, int port, SCH sport_h, SCH sport_l, SCH *seqno, SCH *ackno, SCH *string);`  
Provided a pointer to a buffer for a datagram, the self IPv4 address and the IPv4 address of the remote server, a TCP port number, two halves of a source port number, pointers to 32-bit big endian values for the sequence number and acknowledgement number, and a pointer to a null-terminated C-string, construct a TCP datagram containing the string using these parameters and checksum both the TCP and IP portions, and place the ready-to-send datagram in the buffer. The buffer should be at least `PACKET_SIZE` bytes (see `tcp.h`). The size of the new datagram is returned.

`int tcp_twiddle(SCH *packet, int size, SCH waitfor, SCH *seqno, SCH *ackno, int inc, SCH *err);`  
Provided a pointer to a ready-to-send TCP control packet and its length in bytes (such as that generated by `tcp_template`), the desired TCP flags to wait for, pointers to 32-bit big endian values for the sequence number and acknowledgement number, a number to increment the sequence number, and a pointer to a single `char` for an error code, send the datagram and wait for the desired reply, possibly forever (such as sending a SYN and waiting for SYN+ACK). Both the sequence number and acknowledgement number are updated for future calls. If the return value is zero, the operation failed and an error code is placed in `err` (see `tcp.h`); otherwise the return value is the flags in the reply. Note that this value may be an RST or FIN even if you didn't ask for them as replies.

## Porting it elsewhere

The system-dependent portions are largely in `compat.h`, where you should have the proper `#define`s for your compiler and any needed `#include`s, and `slip.c`, where you should provide the path to your serial port, its speed and the means to make it "raw." You may also need to alter `ntp.c` to properly handle displaying dates from a Unix-epoch `time_t`. If you are porting this to another Unix Version 7 or early System V-derived Unix, you may be able to modify the Venix port to meet your needs. Outside of these files, the remainder make no system-specific calls.

## Don't file issues

... unless you intend to fix them. Bug reports without patches may or may not be addressed on any particular timetable, up to and including the heat death of the known universe.

Although the aim is to be portable, the aim is _not_ to support every possible operating system. This was written for Venix and modern systems. I may add such support myself but only for the operating systems I care about. Your pull request may be rejected on that basis; please don't take it personally, or ask first. You are assumed to be implicitly and irrevocably releasing copyright on any pull request or patch you submit for inclusion.

Feature requests will be handed back over to the grue for an appropriate disposition. He's pretty hungry. He likes the gamey flavour of people who don't read documentation. He just quit GLP-1 shots and that appetite is back.

Certain "issues" are intentionally wontfix. In particular, do not file issues or pull requests about refactoring the C code or making it more modern, or porting it to something other than C -- it's the way it is for a reason.

## Licenses and copyrights

BASS is released under the BSD 2-clause license.

Copyright &copy; 2025, Cameron Kaiser. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
