/*
 * pop3 - a simple pop3 mail client
 *
 * Copyright (C) 2010 Ali Gholami Rudi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, as published by the
 * Free Software Foundation.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "config.h"

#define BUFFSIZE		(1 << 12)
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)		((a) < (b) ? (a) : (b))

struct mailinfo {
	char name[1 << 4];
	int size;
} mails[MAXMAILS];
int nmails;

static int fd;
static char buf[BUFFSIZE];
static char *buf_cur;
static char *buf_end;

#ifdef SSL
#include <polarssl/ssl.h>
#include <polarssl/havege.h>

static ssl_context ssl;
static ssl_session ssn;
static havege_state hs;

static int ps_send(void *ctx, unsigned char *buf, int len)
{
	return write(*(int *) ctx, buf, len);
}

static int ps_recv(void *ctx, unsigned char *buf, int len)
{
	return read(*(int *) ctx, buf, len);
}

#endif

static int pop3_connect(char *addr, char *port)
{
	struct addrinfo hints, *addrinfo;
	int fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(addr, port, &hints, &addrinfo);
	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			addrinfo->ai_protocol);

	if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
		close(fd);
		freeaddrinfo(addrinfo);
		return -1;
	}
	freeaddrinfo(addrinfo);
	return fd;
}

static void print(char *buf, int len)
{
	write(STDOUT_FILENO, buf, len);
}

static int reply_line(char *dst, int len)
{
	int nr = 0;
	char *nl;
	while (nr < len) {
		int ml;
		if (!buf_cur || buf_cur >= buf_end) {
#ifdef SSL
			int buf_len = ssl_read(&ssl, (unsigned char *) buf,
						sizeof(buf));
#else
			int buf_len = read(fd, buf, sizeof(buf));
#endif
			if (buf_len <= 0)
				return -1;
#ifdef DEBUG
			print(buf, buf_len);
#endif
			buf_cur = buf;
			buf_end = buf + buf_len;
		}
		ml = MIN(buf_end - buf_cur, len - nr);
		if ((nl = memchr(buf_cur, '\n', ml))) {
			nl++;
			memcpy(dst + nr, buf_cur, nl - buf_cur);
			nr += nl - buf_cur;
			buf_cur = nl;
			return nr;
		}
		memcpy(dst + nr, buf_cur, ml);
		nr += ml;
		buf_cur += ml;
	}
	return nr;
}

static void send_cmd(char *cmd)
{
#ifdef SSL
	ssl_write(&ssl, (unsigned char *) cmd, strlen(cmd));
#else
	write(fd, cmd, strlen(cmd));
#endif
	fsync(fd);
#ifdef DEBUG
	print(cmd, strlen(cmd));
#endif
}

static int is_eoc(char *line, int len)
{
	return len < 4 && line[0] == '.' &&
		(line[1] == '\r' || line[1] == '\n');
}

static char *putmem(char *dst, char *src, int len)
{
	memcpy(dst, src, len);
	return dst + len;
}

static char *cutword(char *dst, char *s)
{
	while (*s && isspace(*s))
		s++;
	while (*s && !isspace(*s))
		*dst++ = *s++;
	*dst = '\0';
	return s;
}

static char *putstr(char *dst, char *src)
{
	int len = strchr(src, '\0') - src;
	memcpy(dst, src, len + 1);
	return dst + len;
}

static void login(char *user, char *pass)
{
	char line[BUFFSIZE];
	int len;
	char *s = line;
	s = putstr(s, "USER ");
	s = putstr(s, user);
	s = putstr(s, "\n");
	send_cmd(line);
	len = reply_line(line, sizeof(line));
	s = line;
	s = putstr(s, "PASS ");
	s = putstr(s, pass);
	s = putstr(s, "\n");
	send_cmd(line);
	len = reply_line(line, sizeof(line));
}

static void mail_stat(void)
{
	char line[BUFFSIZE];
	int len;
	send_cmd("STAT\n");
	len = reply_line(line, sizeof(line));
	print(line, len);
	send_cmd("LIST\n");
	len = reply_line(line, sizeof(line));
	while ((len = reply_line(line, sizeof(line))) != -1) {
		struct mailinfo *mail;
		char *s = line;
		if (is_eoc(line, len))
			break;
		mail = &mails[nmails++];
		s = cutword(mail->name, s);
		mail->size = atoi(s);
	}
}

static void req_mail(int i)
{
	char cmd[100];
	char *s = cmd;
	s = putstr(s, "RETR ");
	s = putstr(s, mails[i].name);
	s = putstr(s, "\n");
	send_cmd(cmd);
}

static char *mail_dst(char *line, int len)
{
	int i;
	line[len] = '\0';
	for (i = 0; i < ARRAY_SIZE(filters); i++) {
		char *hdr = filters[i].hdr;
		if (!strncmp(hdr, line, strlen(hdr)) &&
				strstr(line, filters[i].val))
			return filters[i].dst;
	}
	return NULL;
}

static int xwrite(int fd, char *buf, int len)
{
	int nw = 0;
	while (nw < len) {
		int ret = write(fd, buf + nw, len - nw);
		if (ret == -1 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret < 0)
			break;
		nw += ret;
	}
	return nw;
}

static int mail_write(char *dst, char *mail, int len)
{
	int fd = open(dst, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd == -1)
		return -1;
	if (xwrite(fd, mail, len) != len)
		return -1;
	close(fd);
	return 0;
}

static char *put_from_(char *s)
{
	time_t t;
	time(&t);
	s = putstr(s, "From ");
	s = putstr(s, getlogin());
	s += strftime(s, MAXSIZE, " %a %b %d %H:%M:%S %Y\n", localtime(&t));
	return s;
}

static int lone_from(char *s)
{
	while (*s == '>')
		s++;
	return !strncmp("From ", s, 5);
}

static int ret_mail(int i)
{
	char mail[MAXSIZE];
	char line[BUFFSIZE];
	char *s = mail;
	int len = reply_line(line, sizeof(line));
	char *dst = NULL;
	int hdr = 1;
	int ret;
	if (mails[i].size + 100 > sizeof(mail))
		return -1;
	print(mails[i].name, strlen(mails[i].name));
	s = put_from_(s);
	while ((len = reply_line(line, sizeof(line))) != -1) {
		if (is_eoc(line, len))
			break;
		if (len > 1 && line[len - 2] == '\r')
			line[len-- - 2] = '\n';
		if (line[0] == '\n')
			hdr = 0;
		if (hdr && !dst)
			dst = mail_dst(line, len);
		if (lone_from(line))
			*s++ = '>';
		s = putmem(s, line, len);
	}
	*s++ = '\n';
	if (!dst)
		dst = SPOOL;
	ret = mail_write(dst, mail, s - mail);
	s = line;
	s = putstr(s, " -> ");
	s = putstr(s, dst);
	s = putstr(s, "\n");
	print(line, s - line);
	return ret;
}

static void del_mail(int i)
{
	char cmd[100];
	char *s = cmd;
	s = putstr(s, "DELE ");
	s = putstr(s, mails[i].name);
	s = putstr(s, "\n");
	send_cmd(cmd);
}

static int fetch(struct account *account, int beg)
{
	char line[BUFFSIZE];
	int len;
	int i;
	char *s = line;
	nmails = 0;
	if ((fd = pop3_connect(account->server, account->port)) == -1)
		return -1;
	s = putstr(s, "fetching ");
	s = putstr(s, account->user);
	s = putstr(s, "@");
	s = putstr(s, account->server);
	s = putstr(s, "\n");
	print(line, s - line);
#ifdef SSL
	havege_init(&hs);
	memset(&ssn, 0, sizeof(ssn));
	if (ssl_init(&ssl))
		return 1;
	ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ssl, SSL_VERIFY_NONE);
	ssl_set_rng(&ssl, havege_rand, &hs);
	ssl_set_bio(&ssl, ps_recv, &fd, ps_send, &fd);
	ssl_set_ciphers(&ssl, ssl_default_ciphers);
	ssl_set_session(&ssl, 1, 600, &ssn);
#endif
	len = reply_line(line, sizeof(line));
	login(account->user, account->pass);
	mail_stat();
	for (i = beg; i < nmails; i++)
		req_mail(i);
	for (i = beg; i < nmails; i++)
		if (ret_mail(i) == -1)
			return 1;
	if (account->del) {
		for (i = beg; i < nmails; i++)
			del_mail(i);
		for (i = beg; i < nmails; i++)
			len = reply_line(line, sizeof(line));
	}
	send_cmd("QUIT\n");
	len = reply_line(line, sizeof(line));
#ifdef SSL
	ssl_close_notify(&ssl);
#endif
	close(fd);
#ifdef SSL
	ssl_free(&ssl);
#endif
	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 0; i < ARRAY_SIZE(accounts); i++) {
		int beg = 0;
		if (argc > i + 1 && isdigit(argv[i + 1][0]))
			beg = atoi(argv[i + 1]);
		if (fetch(&accounts[i], beg) == -1)
			return 1;
	}
	return 0;
}
