/*
 * pop3 - a simple pop3 mail client
 *
 * Copyright (C) 2010-2011 Ali Gholami Rudi
 *
 * This program is released under GNU GPL version 2.
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

static struct mailinfo {
	char name[1 << 4];
	char id[1 << 5];
	int size;
} mails[MAXMAILS];
static int nmails;
static struct uidl *uidl;

static char buf[BUFFSIZE];
static char *buf_cur;
static char *buf_end;
static struct conn *conn;

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
			int buf_len = conn_read(conn, buf, sizeof(buf));
			if (buf_len <= 0)
				return -1;
			DPRINT(buf, buf_len);
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
	conn_write(conn, cmd, strlen(cmd));
	DPRINT(cmd, strlen(cmd));
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
	sprintf(line, "USER %s\n", user);
	send_cmd(line);
	len = reply_line(line, sizeof(line));
	sprintf(line, "PASS %s\n", pass);
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

static void mail_uidl(void)
{
	char line[BUFFSIZE];
	int len;
	int i = 0;
	send_cmd("UIDL\n");
	len = reply_line(line, sizeof(line));
	while ((len = reply_line(line, sizeof(line))) != -1 &&
			!is_eoc(line, len)) {
		char name[100];
		char *s = line;
		s = cutword(name, s);
		s = cutword(mails[i++].id, s);
	}
}

static void req_mail(int i)
{
	char cmd[100];
	sprintf(cmd, "RETR %s\n", mails[i].name);
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
	sprintf(line, " -> %s\n", dst);
	print(line, strlen(line));
	return ret;
}

static void del_mail(int i)
{
	char cmd[100];
	sprintf(cmd, "DELE %s\n", mails[i].name);
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
				reply_line(line, sizeof(line));
	}
	return 0;
}

static int fetch(struct account *account)
{
	char line[BUFFSIZE];
	int len;
	int batch;
	int i;
	nmails = 0;
	conn = conn_connect(account->server, account->port, account->cert);
	if (!conn)
		return -1;
	buf_cur = buf;
	buf_end = buf;
	if (account->uidl)
		uidl = uidl_read(account->uidl);
	sprintf(line, "fetching %s@%s\n", account->user, account->server);
	print(line, strlen(line));
	len = reply_line(line, sizeof(line));
	login(account->user, account->pass);
	mail_stat();
	if (account->uidl)
		mail_uidl();
	batch = account->nopipe ? 1 : nmails;
	for (i = 0; i < nmails; i += batch)
		ret_mails(i, i + batch, account->del);
	send_cmd("QUIT\n");
	len = reply_line(line, sizeof(line));
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
	for (i = 0; i < ARRAY_SIZE(accounts); i++) {
		if (fetch(&accounts[i]) == -1)
			return 1;
	}
	return 0;
}
