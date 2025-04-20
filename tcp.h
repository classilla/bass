#if __GNUC__
int tcp_total32(SCH *value, int inc);
int tcp_template(SCH *packet, SCH *src, SCH *dst, int port, SCH sport_h, SCH sport_l, SCH flags, SCH *seqno, SCH *ackno);
int tcp_transmittal(SCH *packet, SCH *src, SCH *dst, int port, SCH sport_h, SCH sport_l, SCH *seqno, SCH *ackno, SCH *string);
int tcp_twiddle(SCH *packet, int size, SCH waitfor, SCH *seqno, SCH *ackno, int inc, SCH *err);
#else
int tcp_total32();
int tcp_template();
int tcp_transmittal();
int tcp_twiddle();
#endif

#define PACKET_SIZE 1536

/* we use the same MSS and window. many SLIP implementations use 1006
   bytes, but this is for slow systems which may have small buffers. if you
   get disconnects, try going with even less. however, this also limits
   how much you can send with minisock, since it only knows to transmit
   everything in one big TCP datagram at the very beginning. if we make a
   future version, we should try to do something different for sends. */
#define MSS_WINDOW 256

#define	TCP_NOMEM	1
#define	TCP_SLIP_ERROR	2
