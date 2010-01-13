#define SERVER			"server"
#define PORT			"995"
#define USERNAME		"username"
#define PASSWORD		"password"
#define MAXMAILS		(1 << 12)
#define MAXSIZE			(1 << 21)
#define FOLDER			"/home/me/.mailx/"
#define SPOOL			(FOLDER "inbox")
#define DELMAILS		0
#define DEBUG
#define SSL

struct filter {
	char *hdr;
	char *val;
	char *dst;
} filters[] = {
	{"HDR:", "KEY", FOLDER "dst"},
};
