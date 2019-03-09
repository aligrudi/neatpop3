#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "uidl.h"

struct uidl {
	char *txt;
	int fd;
};

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

int uidl_find(struct uidl *uidl, char *id)
{
	char *s = uidl->txt;
	int len = strlen(id);
	while (s && *s) {
		if (!strncmp(s, id, len) && s[len] == '\n')
			return 1;
		s = strchr(s, '\n');
		s = s ? s + 1 : s;
	}
	return 0;
}

void uidl_add(struct uidl *uidl, char *id)
{
	char kw[256];
	snprintf(kw, sizeof(kw), "%s\n", id);
	write(uidl->fd, kw, strlen(kw));
}

void uidl_save(struct uidl *uidl)
{
	close(uidl->fd);
	free(uidl->txt);
	free(uidl);
}
