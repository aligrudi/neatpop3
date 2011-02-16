POLARPATH = /opt
CC = cc
CFLAGS = -Wall -Os -I$(POLARPATH)/include/
LDFLAGS = -L$(POLARPATH)/lib -lpolarssl

all: pop3
.c.o:
	$(CC) -c $(CFLAGS) $<
pop3.o: config.h
pop3: pop3.o uidl.o conn.o
	$(CC) -o $@ $^ $(LDFLAGS)
clean:
	rm -f *.o pop3
