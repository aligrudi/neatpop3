# common options
CC = cc

# for openssl
OBJS = pop3.o uidl.o conn_openssl.o
CFLAGS = -Wall -O2
LDFLAGS = -lssl

# for mbedtls (polarssl)
#OBJS = pop3.o uidl.o conn_mbedtls.o
#CFLAGS = -Wall -O2
#LDFLAGS = -lpolarssl

all: pop3
%.o: %.c conf.h
	$(CC) -c $(CFLAGS) $<
pop3: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	chmod 100 $@
clean:
	rm -f *.o pop3
