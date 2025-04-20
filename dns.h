#if __GNUC__
int dns_dissolve(SCH *name, SCH *src, SCH *dst, SCH *answer);
#else
int dns_dissolve();
#endif

#define DNS_BIG_QUESTION	1
#define DNS_QUESTION_ERROR	2
#define DNS_SLIP_ERROR		3
#define DNS_BAD_ANSWER		4
#define DNS_NO_ANSWERS		5
#define DNS_ANSWER_ERROR	6
#define DNS_NOMEM		7

