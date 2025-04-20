OBJS = ping nslookup ntp minisock
CFLAGS = -O2 -g -std=c89 -DDEBUG
#CFLAGS = -O2 -g -std=c89

all: $(OBJS)

ping: slip.o ping.o
	gcc -o $@ $^

nslookup: nslookup.o slip.o dns.o
	gcc -o $@ $^

minisock: minisock.o tcp.o slip.o dns.o
	gcc -o $@ $^

ntp: ntp.o slip.o dns.o
	gcc -o $@ $^

.c.o:
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(OBJS)
