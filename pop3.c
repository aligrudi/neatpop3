/*
 * pop3 - a simple pop3 mail client
 *
 * Copyright (C) 2010-2013 Ali Gholami Rudi
 *
 * This program is released under the modified BSD license.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "uidl.h"
#include "conn.h"

#define BUFFSIZE		(1 << 12)
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)		((a) < (b) ? (a) : (b))
#define PRINT(s, l)		(write(1, (s), (l)))

static struct mailinfo {
	char name[1 << 4];
	char id[1 << 5];
	int size;
} mails[MAXMAILS];
static int nmails;
static struct uidl *uidl;

static char buf[BUFFSIZE];
static int buf_len;
static int buf_pos;
static struct conn *conn;
static char *mailbuf;

static int pop3_read(void)
{
	if (buf_pos == buf_len) {
		buf_len = conn_read(conn, buf, sizeof(buf));
		buf_pos = 0;
	}
	return buf_pos < buf_len ? (unsigned char) buf[buf_pos++] : -1;
}

static int pop3_line(char *dst, int len)
{
	int i = 0;
	int c;
	while (i < len) {
		c = pop3_read();
		if (c < 0)
			return -1;
		dst[i++] = c;
		if (c == '\n')
			break;
	}
	DPRINT(dst, i);
	return i;
}

static void send_cmd(char *cmd)
{
	conn_write(conn, cmd, strlen(cmd));
	DPRINT(cmd, strlen(cmd));
}

static int is_eoc(char *line, int len)
{
	return len >= 2 && len <= 3 && line[0] == '.' &&
		(line[1] == '\r' || line[1] == '\n');
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

static void login(char *user, char *pass)
{
	char line[BUFFSIZE];
	sprintf(line, "USER %s\r\n", user);
	send_cmd(line);
	pop3_line(line, sizeof(line));
	sprintf(line, "PASS %s\r\n", pass);
	send_cmd(line);
	pop3_line(line, sizeof(line));
}

static void mail_stat(void)
{
	char line[BUFFSIZE];
	int len;
	send_cmd("STAT\r\n");
	len = pop3_line(line, sizeof(line));
	PRINT(line, len);
	send_cmd("LIST\r\n");
	len = pop3_line(line, sizeof(line));
	while ((len = pop3_line(line, sizeof(line))) != -1) {
		struct mailinfo *mail;
		char *s = line;
		if (is_eoc(line, len))
			break;
		mail = &mails[nmails++];
		s = cutword(mail->name, s);
		mail->size = atoi(s);
	}
}

static void mail_uidl(void)
{
	char line[BUFFSIZE];
	char name[100];
	int len;
	int i = 0;
	send_cmd("UIDL\r\n");
	len = pop3_line(line, sizeof(line));
	while ((len = pop3_line(line, sizeof(line))) > 0 && !is_eoc(line, len)) {
		char *s = line;
		s = cutword(name, s);
		s = cutword(mails[i++].id, s);
	}
}

static void req_mail(int i)
{
	char cmd[100];
	sprintf(cmd, "RETR %s\r\n", mails[i].name);
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

static char *putstr(char *dst, char *src)
{
	int len = strchr(src, '\0') - src;
	memcpy(dst, src, len + 1);
	return dst + len;
}

static char *put_from_(char *s)
{
	time_t t;
	time(&t);
	s = putstr(s, "From ");
	s = putstr(s, getenv("USER") ? getenv("USER") : "root");
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
	char line[BUFFSIZE];
	char *s = mailbuf;
	int len = pop3_line(line, sizeof(line));
	char *dst = NULL;
	int hdr = 1;
	int ret;
	PRINT(mails[i].name, strlen(mails[i].name));
	s = put_from_(s);
	while (1) {
		len = pop3_line(line, sizeof(line));
		if (len <= 0)		/* end of stream or error */
			return -1;
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
		memcpy(s, line, len);
		s += len;
	}
	*s++ = '\n';
	if (!dst)
		dst = SPOOL;
	ret = mail_write(dst, mailbuf, s - mailbuf);
	sprintf(line, " -> %s\n", dst);
	PRINT(line, strlen(line));
	return ret;
}

static void del_mail(int i)
{
	char cmd[100];
	sprintf(cmd, "DELE %s\r\n", mails[i].name);
	send_cmd(cmd);
}

static int size_ok(int i)
{
	return mails[i].size + 100 < MAXSIZE;
}

static int uidl_new(int i)
{
	return !uidl || !uidl_find(uidl, mails[i].id);
}

static int ret_mails(int beg, int end, int del)
{
	char line[BUFFSIZE];
	int i;
	for (i = beg; i < end; i++)
		if (size_ok(i) && uidl_new(i))
			req_mail(i);
	for (i = beg; i < end; i++) {
		if (size_ok(i) && uidl_new(i)) {
			if (ret_mail(i) == -1)
				return -1;
			if (uidl)
				uidl_add(uidl, mails[i].id);
		}
	}
	if (del) {
		for (i = beg; i < end; i++)
			if ((!uidl && size_ok(i)) || (uidl && !uidl_new(i)))
				del_mail(i);
		for (i = beg; i < end; i++)
			if ((!uidl && size_ok(i)) || (uidl && !uidl_new(i)))
				pop3_line(line, sizeof(line));
	}
	return 0;
}

static int fetch(struct account *account)
{
	char line[BUFFSIZE];
	int batch;
	int i;
	nmails = 0;
	conn = conn_connect(account->server, account->port, account->cert);
	if (!conn)
		return -1;
	buf_pos = 0;
	buf_len = 0;
	if (account->uidl)
		uidl = uidl_read(account->uidl);
	sprintf(line, "fetching %s@%s\n", account->user, account->server);
	PRINT(line, strlen(line));
	pop3_line(line, sizeof(line));
	login(account->user, account->pass);
	mail_stat();
	if (account->uidl)
		mail_uidl();
	batch = account->nopipe ? 1 : nmails;
	for (i = 0; i < nmails; i += batch)
		ret_mails(i, MIN(nmails, i + batch), account->del);
	send_cmd("QUIT\r\n");
	pop3_line(line, sizeof(line));
	conn_close(conn);
	if (uidl)
		uidl_save(uidl);
	uidl = NULL;
	return 0;
}

static void sigint(int sig)
{
	if (uidl)
		uidl_save(uidl);
	exit(1);
}

int main(int argc, char *argv[])
{
	int i;
	signal(SIGINT, sigint);
	mailbuf = malloc(MAXSIZE);
	for (i = 0; i < ARRAY_SIZE(accounts); i++)
		if (fetch(&accounts[i]) == -1)
			return 1;
	free(mailbuf);
	return 0;
}
