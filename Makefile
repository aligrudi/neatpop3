POLARPATH = /opt
CC = diet cc
CFLAGS = -std=gnu89 -pedantic -Wall -O2 -I$(POLARPATH)/include
LDFLAGS = -s

all: pop3
.c.o:
	$(CC) -c $(CFLAGS) $<
pop3.o: config.h
pop3: pop3.o $(POLARPATH)/lib*/libpolarssl.a
	$(CC) $(LDFLAGS) -o $@ $^
clean:
	rm -f *.o pop3
ctags:
	ctags *.[hc]
