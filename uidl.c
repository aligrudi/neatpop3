#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "uidl.h"

static int file_size(int fd)
{
	struct stat st;
	fstat(fd, &st);
	return st.st_size;
}

static int xread(int fd, char *buf, int len)
{
	int nr = 0;
	while (nr < len) {
		int cr = read(fd, buf + nr, len - nr);
		if (cr == -1)
			break;
		nr += cr;
	}
	return nr;
}

struct uidl *uidl_read(char *filename)
{
	struct uidl *uidl = malloc(sizeof(*uidl));
	int len;
	uidl->fd = open(filename, O_RDWR | O_CREAT, 0600);
	len = file_size(uidl->fd);
	lseek(uidl->fd, 0, SEEK_SET);
	uidl->txt = malloc(len + 1);
	xread(uidl->fd, uidl->txt, len);
	uidl->txt[len] = '\0';
	lseek(uidl->fd, 0, SEEK_END);
	return uidl;
}

static char *putnl(char *dst, char *src)
{
	while (*src)
		*dst++ = *src++;
	*dst++ = '\n';
	*dst = '\0';
	return dst;
}

int uidl_find(struct uidl *uidl, char *id)
{
	char kw[128];
	putnl(kw, id);
	return !!strstr(uidl->txt, kw);
}

void uidl_add(struct uidl *uidl, char *id)
{
	char kw[128];
	int len = putnl(kw, id) - kw;
	write(uidl->fd, kw, len);
}

void uidl_save(struct uidl *uidl)
{
	close(uidl->fd);
	free(uidl->txt);
	free(uidl);
}