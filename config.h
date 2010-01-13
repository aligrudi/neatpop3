#define MAXMAILS		(1 << 12)
#define MAXSIZE			(1 << 21)
#define FOLDER			"/home/me/.mailx/"
#define SPOOL			(FOLDER "inbox")
#define DELMAILS		0
#define SSL

struct account {
	char *server;
	char *port;
	char *user;
	char *pass;
} accounts [] = {
	{"server", "port", "username", "password"},
};

struct filter {
	char *hdr;
	char *val;
	char *dst;
} filters[] = {
	{"HDR:", "KEY", FOLDER "dst"},
};
