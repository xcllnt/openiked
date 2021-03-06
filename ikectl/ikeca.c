/*	$OpenBSD: ikeca.c,v 1.40 2015/11/02 12:21:27 jsg Exp $	*/

/*
 * Copyright (c) 2010 Jonathan Gray <jsg@openbsd.org>
 * Copyright (c) 2016 Marcel Moolenaar <marcel@FreeBSD.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <fcntl.h>
#include <fts.h>
#include <dirent.h>
#include <limits.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "types.h"
#include "parser.h"

#ifndef PREFIX
#define PREFIX		""
#endif
#ifndef SSLDIR
#define SSLDIR		PREFIX "/etc/ssl"
#endif
#define SSL_CNF		SSLDIR "/openssl.cnf"
#define X509_CNF	SSLDIR "/x509v3.cnf"
#define IKECA_CNF	PREFIX "/etc/ikeca.cnf"
#define KEYBASE		PREFIX "/etc/iked"
#ifndef EXPDIR
#define EXPDIR		PREFIX "/usr/share/iked"
#endif

#ifndef PATH_OPENSSL
#define PATH_OPENSSL	"/usr/bin/openssl"
#endif
#ifndef PATH_ZIP
#define PATH_ZIP	"/usr/local/bin/zip"
#endif
#ifndef PATH_TAR
#define PATH_TAR	"/bin/tar"
#endif

static struct ca *ca_issuer(struct ca *);
static int ca_revoke_internal(struct ca *, char *);

struct ca {
	char		 sslpath[PATH_MAX];
	char		 passfile[PATH_MAX];
	char		 index[PATH_MAX];
	char		 serial[PATH_MAX];
	char		 sslcnf[PATH_MAX];
	char		 extcnf[PATH_MAX];
	char		 batch[PATH_MAX];
	char		*caname;
};

struct {
	char	*dir;
	mode_t	 mode;
} hier[] = {
	{ "",		0755 },
	{ "/ca",	0755 },
	{ "/certs",	0755 },
	{ "/crls",	0755 },
	{ "/export",	0755 },
	{ "/private",	0700 }
};

/* explicitly list allowed variables */
const char *ca_env[][2] = {
	{ "$ENV::CADB", NULL },
	{ "$ENV::CASERIAL", NULL },
	{ "$ENV::CERTFQDN", NULL },
	{ "$ENV::CERTIP", NULL },
	{ "$ENV::CERTPATHLEN", NULL },
	{ "$ENV::CERTUSAGE", NULL },
	{ "$ENV::CERT_C", NULL },
	{ "$ENV::CERT_CN", NULL },
	{ "$ENV::CERT_EMAIL", NULL },
	{ "$ENV::CERT_L", NULL },
	{ "$ENV::CERT_O", NULL },
	{ "$ENV::CERT_OU", NULL },
	{ "$ENV::CERT_ST", NULL },
	{ "$ENV::EXTCERTUSAGE", NULL },
	{ "$ENV::NSCERTTYPE", NULL },
	{ NULL }
};

int		 ca_sign(struct ca *, char *, int);
int		 ca_request(struct ca *, char *);
void		 ca_newpass(char *, char *);
char		*ca_readpass(char *, size_t *);
int		 fcopy(char *, char *, mode_t);
void		 fcopy_env(const char *, const char *, mode_t);
int		 rm_dir(char *);
void		 ca_hier(char *);
void		 ca_setenv(const char *, const char *);
void		 ca_clrenv(void);
void		 ca_setcnf(struct ca *, const char *);
void		 ca_create_index(struct ca *);

/* util.c */
int		 expand_string(char *, size_t, const char *, const char *);

int
ca_delete(struct ca *ca)
{
	char		 path[PATH_MAX];
	struct ca	*issuer;

	issuer = ca_issuer(ca);
	if (issuer) {
		snprintf(path, sizeof(path), "%s/intermediates/%s",
		    issuer->sslpath, ca->caname);
		unlink(path);
	}
	return (rm_dir(ca->sslpath));
}

int
ca_key_create(struct ca *ca, char *keyname)
{
	struct stat		 st;
	char			 cmd[PATH_MAX * 2];
	char			 path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/private/%s.key", ca->sslpath,
	    keyname);

	/* don't recreate key if one is already present */
	if (stat(path, &st) == 0) {
		return (0);
	}

	snprintf(cmd, sizeof(cmd),
	    "%s genrsa -out %s 2048",
	    PATH_OPENSSL, path);
	system(cmd);
	chmod(path, 0600);

	return (0);
}

int
ca_key_import(struct ca *ca, char *keyname, char *import)
{
	struct stat		 st;
	char			 dst[PATH_MAX];

	if (stat(import, &st) != 0) {
		warn("could not access keyfile %s", import);
		return (1);
	}

	snprintf(dst, sizeof(dst), "%s/private/%s.key", ca->sslpath, keyname);
	fcopy(import, dst, 0600);

	return (0);
}

int
ca_key_delete(struct ca *ca, char *keyname)
{
	char			 path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/private/%s.key", ca->sslpath,
	    keyname);
	unlink(path);

	return (0);
}

int
ca_delkey(struct ca *ca, char *keyname)
{
	char		file[PATH_MAX];

	snprintf(file, sizeof(file), "%s/%s.crt", ca->sslpath, keyname);
	unlink(file);

	snprintf(file, sizeof(file), "%s/private/%s.key", ca->sslpath,
	    keyname);
	unlink(file);

	snprintf(file, sizeof(file), "%s/private/%s.csr", ca->sslpath,
	    keyname);
	unlink(file);

	snprintf(file, sizeof(file), "%s/private/%s.pfx", ca->sslpath,
	    keyname);
	unlink(file);

	return (0);
}

int
ca_request(struct ca *ca, char *keyname)
{
	char		cmd[PATH_MAX * 2];
	char		path[PATH_MAX];

	ca_setenv("$ENV::CERT_CN", keyname);
	ca_setcnf(ca, keyname);

	snprintf(path, sizeof(path), "%s/private/%s.csr", ca->sslpath, keyname);
	snprintf(cmd, sizeof(cmd), "%s req %s-new"
	    " -key %s/private/%s.key -out %s -config %s",
	    PATH_OPENSSL, ca->batch, ca->sslpath, keyname,
	    path, ca->sslcnf);

	system(cmd);
	chmod(path, 0600);

	return (0);
}

int
ca_sign(struct ca *ca, char *keyname, int type)
{
	char		cmd[PATH_MAX * 2];
	char		hostname[_POSIX_HOST_NAME_MAX+1];
	char		name[128];
	const char	*extensions = NULL;

	strlcpy(name, keyname, sizeof(name));

	if (type == HOST_IPADDR) {
		ca_setenv("$ENV::CERTIP", name);
		extensions = "x509v3_IPAddr";
	} else if (type == HOST_FQDN) {
		if (!strcmp(keyname, "local")) {
			if (gethostname(hostname, sizeof(hostname)))
				err(1, "gethostname");
			strlcpy(name, hostname, sizeof(name));
		}
		ca_setenv("$ENV::CERTFQDN", name);
		extensions = "x509v3_FQDN";
	} else {
		errx(1, "unknown host type %d", type);
	}

	ca_create_index(ca);

	ca_setenv("$ENV::CADB", ca->index);
	ca_setenv("$ENV::CASERIAL", ca->serial);
	ca_setcnf(ca, keyname);

	snprintf(cmd, sizeof(cmd),
	    "%s ca -config %s -keyfile %s/private/%s-ca.key"
	    " -cert %s/%s-ca.crt"
	    " -extfile %s -extensions %s -out %s/%s.crt"
	    " -in %s/private/%s.csr"
	    " -passin file:%s -outdir %s -batch",
	    PATH_OPENSSL, ca->sslcnf, ca->sslpath, ca->caname,
	    ca->sslpath, ca->caname,
	    ca->extcnf, extensions, ca->sslpath, keyname,
	    ca->sslpath, keyname,
	    ca->passfile, ca->sslpath);

	system(cmd);

	return (0);
}

int
ca_certificate(struct ca *ca, char *keyname, int type, int action)
{
	ca_clrenv();

	switch (action) {
	case CA_SERVER:
		ca_setenv("$ENV::EXTCERTUSAGE", "serverAuth");
		ca_setenv("$ENV::NSCERTTYPE", "server");
		ca_setenv("$ENV::CERTUSAGE",
		    "digitalSignature,keyEncipherment");
		break;
	case CA_CLIENT:
		ca_setenv("$ENV::EXTCERTUSAGE", "clientAuth");
		ca_setenv("$ENV::NSCERTTYPE", "client");
		ca_setenv("$ENV::CERTUSAGE",
		    "digitalSignature,keyAgreement");
		break;
	case CA_OCSP:
		ca_setenv("$ENV::EXTCERTUSAGE", "OCSPSigning");
		ca_setenv("$ENV::CERTUSAGE",
		    "nonRepudiation,digitalSignature,keyEncipherment");
		break;
	default:
		break;
	}

	ca_key_create(ca, keyname);
	ca_request(ca, keyname);
	ca_sign(ca, keyname, type);

	return (0);
}

int
ca_key_install(struct ca *ca, char *keyname, char *dir)
{
	struct stat	 st;
	char		 cmd[PATH_MAX * 2];
	char		 src[PATH_MAX];
	char		 dst[PATH_MAX];
	char		*p = NULL;

	snprintf(src, sizeof(src), "%s/private/%s.key", ca->sslpath, keyname);
	if (stat(src, &st) == -1) {
		if (errno == ENOENT)
			printf("key for '%s' does not exist\n", ca->caname);
		else
			warn("could not access key");
		return (1);
	}

	if (dir == NULL)
		p = dir = strdup(KEYBASE);

	ca_hier(dir);

	snprintf(dst, sizeof(dst), "%s/private/local.key", dir);
	fcopy(src, dst, 0600);

	snprintf(cmd, sizeof(cmd), "%s rsa -out %s/local.pub"
	    " -in %s/private/local.key -pubout", PATH_OPENSSL, dir, dir);
	system(cmd);

	free(p);

	return (0);
}

int
ca_cert_install(struct ca *ca, char *keyname, char *dir)
{
	char		 src[PATH_MAX];
	char		 dst[PATH_MAX];
	int		 r;
	char		*p = NULL;

	if (dir == NULL)
		p = dir = strdup(KEYBASE);

	ca_hier(dir);

	if ((r = ca_key_install(ca, keyname, dir)) != 0) {
		free(dir);
		return (r);
	}

	snprintf(src, sizeof(src), "%s/%s.crt", ca->sslpath, keyname);
	snprintf(dst, sizeof(dst), "%s/certs/%s.crt", dir, keyname);
	fcopy(src, dst, 0644);

	free(p);

	return (0);
}

void
ca_newpass(char *passfile, char *password)
{
	FILE	*f;
	char	*pass;
	char	 prev[_PASSWORD_LEN + 1];

	if (password != NULL) {
		pass = password;
		goto done;
	}

	pass = getpass("CA passphrase:");
	if (pass == NULL || *pass == '\0')
		err(1, "password not set");

	strlcpy(prev, pass, sizeof(prev));
	pass = getpass("Retype CA passphrase:");
	if (pass == NULL || strcmp(prev, pass) != 0)
		errx(1, "passphrase does not match!");

 done:
	if ((f = fopen(passfile, "wb")) == NULL)
		err(1, "could not open passfile %s", passfile);
	chmod(passfile, 0600);

	fprintf(f, "%s\n%s\n", pass, pass);

	fclose(f);
}

static int
ca_create_internal(struct ca *ca, struct ca *issuer)
{
	char			 cmd[PATH_MAX * 2];
	char			 cn[PATH_MAX];
	char			 name[PATH_MAX];
	char			 path[PATH_MAX];

	ca_clrenv();

	snprintf(name, sizeof(name), "%s-ca", ca->caname);
	snprintf(path, sizeof(path), "%s/private/%s.key", ca->sslpath, name);
	snprintf(cmd, sizeof(cmd), "%s genrsa -aes256 -out"
	    " %s -passout file:%s 2048", PATH_OPENSSL, path, ca->passfile);
	system(cmd);
	chmod(path, 0600);

	snprintf(cn, sizeof(cn), "%s %s CA", ca->caname,
	    (issuer == ca) ? "root" : "intermediate");
	ca_setenv("$ENV::CERT_CN", cn);
	ca_setcnf(issuer, name);

	snprintf(path, sizeof(path), "%s/private/%s.csr", issuer->sslpath,
	    name);
	snprintf(cmd, sizeof(cmd), "%s req %s-new -key %s/private/%s.key"
	    " -config %s -out %s -passin file:%s", PATH_OPENSSL, ca->batch,
	    ca->sslpath, name, issuer->sslcnf, path, ca->passfile);
	system(cmd);
	chmod(path, 0600);

	if (issuer == ca) {
		snprintf(cmd, sizeof(cmd), "%s x509 -req -days 365"
		    " -in %s/private/%s.csr -signkey %s/private/%s.key"
		    " -sha256 -extfile %s -extensions x509v3_CA"
		    " -out %s/%s.crt -passin file:%s", PATH_OPENSSL,
		    issuer->sslpath, name, ca->sslpath, name, issuer->extcnf,
		    ca->sslpath, name, ca->passfile);
		system(cmd);
	} else {
		ca_create_index(issuer);
		ca_clrenv();
		ca_setenv("$ENV::CERT_CN", cn);
		ca_setenv("$ENV::CADB", issuer->index);
		ca_setenv("$ENV::CASERIAL", issuer->serial);
		ca_setcnf(issuer, name);

		snprintf(cmd, sizeof(cmd), "%s ca -config %s -notext"
		    " -keyfile %s/private/%s-ca.key -cert %s/%s-ca.crt"
		    " -extfile %s -extensions x509v3_CA -out %s/%s.crt"
		    " -in %s/private/%s.csr -passin file:%s -outdir %s"
		    " -batch", PATH_OPENSSL, issuer->sslcnf, issuer->sslpath,
		    issuer->caname, issuer->sslpath, issuer->caname,
		    issuer->extcnf, ca->sslpath, name, issuer->sslpath,
		    name, issuer->passfile, issuer->sslpath);
		system(cmd);
	}

	ca_clrenv();
	ca_setenv("$ENV::CERT_CN", cn);
	ca_setcnf(issuer, name);

	/* Create the CRL revocation list */
	ca_revoke_internal(ca, NULL);

	return (0);
}

int
ca_create(struct ca *ca)
{

	return (ca_create_internal(ca, ca));
}

int
ca_install(struct ca *ca, char *dir)
{
	struct stat	 st;
	char		 src[PATH_MAX];
	char		 dst[PATH_MAX];
	char		*p = NULL;

	if (dir == NULL)
		p = dir = strdup(KEYBASE);

	ca_hier(dir);

	while (ca != NULL) {
		snprintf(src, sizeof(src), "%s/%s-ca.crt", ca->sslpath,
		    ca->caname);
		if (stat(src, &st) == -1) {
			printf("CA '%s' does not exist\n", ca->caname);
			break;
		}
		snprintf(dst, sizeof(dst), "%s/ca/%s-ca.crt", dir,
		    ca->caname);
		if (fcopy(src, dst, 0644) == 0)
			printf("certificate for CA '%s' installed into %s\n",
			    ca->caname, dst);

		snprintf(src, sizeof(src), "%s/%s-ca.crl", ca->sslpath,
		    ca->caname);
		if (stat(src, &st) == 0) {
			snprintf(dst, sizeof(dst), "%s/crls/%s-ca.crl", dir,
			    ca->caname);
			if (fcopy(src, dst, 0644) == 0)
				printf("CRL for CA '%s' installed to %s\n",
				    ca->caname, dst);
		}

		ca = ca_issuer(ca);
	}

	free(p);
	return ((ca == NULL) ? 0 : 1);
}

int
ca_show_certs(struct ca *ca, char *name)
{
	DIR		*dir;
	struct dirent	*de;
	char		 cmd[PATH_MAX * 2];
	char		 path[PATH_MAX];
	char		*p;
	struct stat	 st;

	if (name != NULL) {
		snprintf(path, sizeof(path), "%s/%s.crt",
		    ca->sslpath, name);
		if (stat(path, &st) != 0)
			err(1, "could not open file %s.crt", name);
		snprintf(cmd, sizeof(cmd), "%s x509 -text"
		    " -in %s", PATH_OPENSSL, path);
		system(cmd);
		printf("\n");
		return (0);
	}

	if ((dir = opendir(ca->sslpath)) == NULL)
		err(1, "could not open directory %s", ca->sslpath);

	while ((de = readdir(dir)) != NULL) {
		if (strlen(de->d_name) > 4) {
			p = de->d_name + strlen(de->d_name) - 4;
			if (strcmp(".crt", p) != 0)
				continue;
			snprintf(path, sizeof(path), "%s/%s", ca->sslpath,
			    de->d_name);
			snprintf(cmd, sizeof(cmd), "%s x509 -subject"
			    " -fingerprint -dates -noout -in %s",
			    PATH_OPENSSL, path);
			system(cmd);
			printf("\n");
		}
	}

	closedir(dir);

	return (0);
}

int
fcopy(char *src, char *dst, mode_t mode)
{
	int		ifd, ofd;
	uint8_t		buf[BUFSIZ];
	ssize_t		r;

	if ((ifd = open(src, O_RDONLY)) == -1)
		err(1, "open %s", src);

	if ((ofd = open(dst, O_WRONLY|O_CREAT|O_TRUNC, mode)) == -1) {
		int saved_errno = errno;
		close(ifd);
		errc(1, saved_errno, "open %s", dst);
	}

	while ((r = read(ifd, buf, sizeof(buf))) > 0) {
		write(ofd, buf, r);
	}

	close(ofd);
	close(ifd);

	return (r == -1);
}

void
fcopy_env(const char *src, const char *dst, mode_t mode)
{
	int		 ofd = -1, i;
	uint8_t		 buf[BUFSIZ];
	ssize_t		 r = -1, len;
	FILE		*ifp = NULL;
	int		 saved_errno;

	if ((ifp = fopen(src, "r")) == NULL)
		err(1, "fopen %s", src);

	if ((ofd = open(dst, O_WRONLY|O_CREAT|O_TRUNC, mode)) == -1)
		goto done;

	while (fgets(buf, sizeof(buf), ifp) != NULL) {
		for (i = 0; ca_env[i][0] != NULL; i++) {
			if (ca_env[i][1] == NULL)
				continue;
			if (expand_string(buf, sizeof(buf),
			    ca_env[i][0], ca_env[i][1]) == -1)
				errx(1, "env %s value too long", ca_env[i][0]);
		}
		len = strlen(buf);
		if (write(ofd, buf, len) != len)
			goto done;
	}

	r = 0;

 done:
	saved_errno = errno;
	close(ofd);
	if (ifp != NULL)
		fclose(ifp);
	if (r == -1)
		errc(1, saved_errno, "open %s", dst);
}

int
rm_dir(char *path)
{
	FTS		*fts;
	FTSENT		*p;
	static char	*fpath[] = { NULL, NULL };

	fpath[0] = path;
	if ((fts = fts_open(fpath, FTS_PHYSICAL, NULL)) == NULL) {
		warn("fts_open %s", path);
		return (1);
	}

	while ((p = fts_read(fts)) != NULL) {
		switch (p->fts_info) {
		case FTS_DP:
		case FTS_DNR:
			if (rmdir(p->fts_accpath) == -1)
				warn("rmdir %s", p->fts_accpath);
			break;
		case FTS_F:
		case FTS_SL:
			if (unlink(p->fts_accpath) == -1)
				warn("unlink %s", p->fts_accpath);
			break;
		case FTS_D:
		case FTS_DOT:
		default:
			continue;
		}
	}
	fts_close(fts);

	return (0);
}

void
ca_hier(char *path)
{
	struct stat	 st;
	char		 dst[PATH_MAX];
	unsigned int	 i;

	for (i = 0; i < nitems(hier); i++) {
		strlcpy(dst, path, sizeof(dst));
		strlcat(dst, hier[i].dir, sizeof(dst));
		if (stat(dst, &st) != 0 && errno == ENOENT &&
		    mkdir(dst, hier[i].mode) != 0)
			err(1, "failed to create dir %s", dst);
	}
}

int
ca_export(struct ca *ca, char *keyname, char *myname, char *password)
{
	DIR		*dexp;
	struct dirent	*de;
	struct stat	 st;
	char		*pass;
	char		 prev[_PASSWORD_LEN + 1];
	char		 cmd[PATH_MAX * 2];
	char		 oname[PATH_MAX];
	char		 src[PATH_MAX];
	char		 dst[PATH_MAX];
	char		*p;
	char		 tpl[] = "/tmp/ikectl.XXXXXXXXXX";
	unsigned int	 i;
	int		 fd;

	if (keyname != NULL) {
		if (strlcpy(oname, keyname, sizeof(oname)) >= sizeof(oname))
			errx(1, "name too long");
	} else {
		snprintf(oname, sizeof(oname), "%s-ca", ca->caname);
	}

	/* colons are not valid characters in windows filenames... */
	while ((p = strchr(oname, ':')) != NULL)
		*p = '_';

	if (password != NULL)
		pass = password;
	else {
		pass = getpass("Export passphrase:");
		if (pass == NULL || *pass == '\0')
			err(1, "password not set");

		strlcpy(prev, pass, sizeof(prev));
		pass = getpass("Retype export passphrase:");
		if (pass == NULL || strcmp(prev, pass) != 0)
			errx(1, "passphrase does not match!");
	}

	if ((p = mkdtemp(tpl)) == NULL)
		err(1, "could not create temp dir");
	chmod(p, 0755);

	for (i = 0; i < nitems(hier); i++) {
		strlcpy(dst, p, sizeof(dst));
		strlcat(dst, hier[i].dir, sizeof(dst));
		if (stat(dst, &st) != 0 && errno == ENOENT &&
		    mkdir(dst, hier[i].mode) != 0) {
			warn("failed to create dir %s", dst);
			goto fail;
		}
	}

	/* create a file with the address of the peer to connect to */
	if (myname != NULL) {
		snprintf(dst, sizeof(dst), "%s/export/peer.txt", p);
		if ((fd = open(dst, O_WRONLY|O_CREAT, 0644)) == -1) {
			warn("open %s", dst);
			goto fail;
		}
		write(fd, myname, strlen(myname));
		close(fd);
	}

	if (keyname != NULL) {
		snprintf(cmd, sizeof(cmd), "env EXPASS=%s %s pkcs12 -export"
		    " -name %s -CAfile %s/%s-ca.crt -inkey %s/private/%s.key"
		    " -in %s/%s.crt -out %s/export/%s.pfx -passout env:EXPASS"
		    " -passin file:%s", pass, PATH_OPENSSL, keyname,
		    ca->sslpath, ca->caname, ca->sslpath, keyname, ca->sslpath,
		    keyname, p, oname, ca->passfile);
		system(cmd);

		snprintf(src, sizeof(src), "%s/private/%s.key", ca->sslpath,
		    keyname);
		snprintf(dst, sizeof(dst), "%s/private/%s.key", p, keyname);
		fcopy(src, dst, 0600);
		snprintf(dst, sizeof(dst), "%s/private/local.key", p);
		fcopy(src, dst, 0600);

		snprintf(src, sizeof(src), "%s/%s.crt", ca->sslpath, keyname);
		snprintf(dst, sizeof(dst), "%s/certs/%s.crt", p, keyname);
		fcopy(src, dst, 0644);

		snprintf(cmd, sizeof(cmd), "%s rsa -out %s/local.pub"
		    " -in %s/private/%s.key -pubout", PATH_OPENSSL, p,
		    ca->sslpath, keyname);
		system(cmd);
	}

	while (ca != NULL) {
		snprintf(cmd, sizeof(cmd), "env EXPASS=%s %s pkcs12 -export"
		    " -caname '%s' -name '%s' -cacerts -nokeys"
		    " -in %s/%s-ca.crt -out %s/export/%s-ca.pfx"
		    " -passout env:EXPASS -passin file:%s", pass,
		    PATH_OPENSSL, ca->caname, ca->caname, ca->sslpath,
		    ca->caname, p, ca->caname, ca->passfile);
		system(cmd);

		snprintf(src, sizeof(src), "%s/%s-ca.crt", ca->sslpath,
		    ca->caname);
		snprintf(dst, sizeof(dst), "%s/ca/%s-ca.crt", p, ca->caname);
		fcopy(src, dst, 0644);

		snprintf(src, sizeof(src), "%s/%s-ca.crl", ca->sslpath,
		    ca->caname);
		if (stat(src, &st) == 0) {
			snprintf(dst, sizeof(dst), "%s/crls/%s-ca.crl", p,
			    ca->caname);
			fcopy(src, dst, 0644);
		}

		ca = ca_issuer(ca);
	}

	if (stat(PATH_TAR, &st) == 0) {
		snprintf(cmd, sizeof(cmd), "%s -zcf %s.tgz -C %s .",
		    PATH_TAR, oname, p);
		system(cmd);
		snprintf(src, sizeof(src), "%s.tgz", oname);
		if (realpath(src, dst) != NULL)
			printf("exported files in %s\n", dst);
	}

	if (stat(PATH_ZIP, &st) == 0) {
		dexp = opendir(EXPDIR);
		if (dexp) {
			while ((de = readdir(dexp)) != NULL) {
				if (!strcmp(de->d_name, ".") ||
				    !strcmp(de->d_name, ".."))
					continue;
				snprintf(src, sizeof(src), "%s/%s", EXPDIR,
				    de->d_name);
				snprintf(dst, sizeof(dst), "%s/export/%s", p,
				    de->d_name);
				fcopy(src, dst, 0644);
			}
			closedir(dexp);
		}

		snprintf(dst, sizeof(dst), "%s/export", p);
		if (getcwd(src, sizeof(src)) == NULL) {
			warn("could not get cwd");
			goto fail;
		}
		if (chdir(dst) == -1) {
			warn("could not change %s", dst);
			goto fail;
		}
		snprintf(dst, sizeof(dst), "%s/%s.zip", src, oname);
		snprintf(cmd, sizeof(cmd), "%s -qr %s .", PATH_ZIP, dst);
		system(cmd);
		printf("exported files in %s\n", dst);

		if (chdir(src) == -1) {
			warn("could not change %s", dst);
			goto fail;
		}
	}

	rm_dir(p);
	return (0);

 fail:
	rm_dir(p);
	return (1);
}

char *
ca_readpass(char *path, size_t *len)
{
	FILE		*f;
	char		*p, *r;

	if ((f = fopen(path, "r")) == NULL) {
		warn("fopen %s", path);
		return (NULL);
	}

	if ((p = fgetln(f, len)) != NULL) {
		if ((r = malloc(*len + 1)) == NULL)
			err(1, "malloc");
		memcpy(r, p, *len);
		if (r[*len - 1] == '\n')
			r[*len - 1] = '\0';
		else
			r[*len] = '\0';
	} else
		r = NULL;

	fclose(f);

	return (r);
}

/* create index if it doesn't already exist */
void
ca_create_index(struct ca *ca)
{
	struct stat	 st;
	int		 fd;

	if (snprintf(ca->index, sizeof(ca->index), "%s/index.txt",
	    ca->sslpath) < 0)
		err(1, "snprintf");
	if (stat(ca->index, &st) != 0) {
		if  (errno == ENOENT) {
			if ((fd = open(ca->index, O_WRONLY | O_CREAT, 0644))
			    == -1)
				err(1, "could not create file %s", ca->index);
			close(fd);
		} else
			err(1, "could not access %s", ca->index);
	}

	if (snprintf(ca->serial, sizeof(ca->serial), "%s/serial.txt",
	    ca->sslpath) < 0)
		err(1, "snprintf");
	if (stat(ca->serial, &st) != 0) {
		if  (errno == ENOENT) {
			if ((fd = open(ca->serial, O_WRONLY | O_CREAT, 0644))
			    == -1)
				err(1, "could not create file %s", ca->serial);
			/* serial file must be created with a number */
			if (write(fd, "01\n", 3) != 3)
				err(1, "write %s", ca->serial);
			close(fd);
		} else
			err(1, "could not access %s", ca->serial);
	}
}

static int
ca_revoke_internal(struct ca *ca, char *certfile)
{
	struct stat	 st;
	char		 cmd[PATH_MAX * 2];
	char		 path[PATH_MAX];
	char		*pass;
	size_t		 len;

	if (certfile) {
		if (stat(certfile, &st) != 0) {
			warn("Problem with certificate '%s'", certfile);
			return (1);
		}
	}

	snprintf(path, sizeof(path), "%s/ikeca.passwd", ca->sslpath);
	pass = ca_readpass(path, &len);
	if (pass == NULL)
		errx(1, "could not open passphrase file");

	ca_create_index(ca);

	ca_setenv("$ENV::CADB", ca->index);
	ca_setenv("$ENV::CASERIAL", ca->serial);
	ca_setcnf(ca, "ca-revoke");

	if (certfile) {
		snprintf(cmd, sizeof(cmd),
		    "%s ca %s-config %s -keyfile %s/private/%s-ca.key"
		    " -key %s"
		    " -cert %s/%s-ca.crt"
		    " -revoke %s",
		    PATH_OPENSSL, ca->batch, ca->sslcnf,
		    ca->sslpath, ca->caname, pass, ca->sslpath, ca->caname,
		    certfile);
		system(cmd);
	}

	snprintf(cmd, sizeof(cmd),
	    "%s ca %s-config %s -keyfile %s/private/%s-ca.key"
	    " -key %s"
	    " -gencrl"
	    " -cert %s/%s-ca.crt"
	    " -crldays 365"
	    " -out %s/%s-ca.crl",
	    PATH_OPENSSL, ca->batch, ca->sslcnf, ca->sslpath, ca->caname,
	    pass, ca->sslpath, ca->caname, ca->sslpath, ca->caname);
	system(cmd);

	explicit_bzero(pass, len);
	free(pass);

	return (0);
}

int
ca_revoke(struct ca *ca, char *keyname)
{
	char		 certfile[PATH_MAX];

	snprintf(certfile, sizeof(certfile), "%s/%s.crt",
	    ca->sslpath, keyname);
	return (ca_revoke_internal(ca, certfile));
}

void
ca_clrenv(void)
{
	int	 i;

	for (i = 0; ca_env[i][0] != NULL; i++)
		ca_env[i][1] = NULL;
}

void
ca_setenv(const char *key, const char *value)
{
	int	 i;

	for (i = 0; ca_env[i][0] != NULL; i++) {
		if (strcmp(ca_env[i][0], key) == 0) {
			if (ca_env[i][1] != NULL)
				errx(1, "env %s already set: %s", key, value);
			ca_env[i][1] = value;
			return;
		}
	}
	errx(1, "env %s invalid", key);
}

void
ca_setcnf(struct ca *ca, const char *keyname)
{
	struct stat	 st;
	const char	*extcnf, *sslcnf;

	if (stat(IKECA_CNF, &st) == 0) {
		extcnf = IKECA_CNF;
		sslcnf = IKECA_CNF;
	} else {
		extcnf = X509_CNF;
		sslcnf = SSL_CNF;
	}

	snprintf(ca->extcnf, sizeof(ca->extcnf), "%s/%s-ext.cnf",
	    ca->sslpath, keyname);
	snprintf(ca->sslcnf, sizeof(ca->sslcnf), "%s/%s-ssl.cnf",
	    ca->sslpath, keyname);

	fcopy_env(extcnf, ca->extcnf, 0400);
	fcopy_env(sslcnf, ca->sslcnf, 0400);
}

struct ca *
ca_setup(char *caname, int create, int quiet, char *pass)
{
	struct stat	 st;
	struct ca	*ca;
	char		 path[PATH_MAX];

	if (stat(PATH_OPENSSL, &st) == -1)
		err(1, "openssl binary not available");

	if ((ca = calloc(1, sizeof(struct ca))) == NULL)
		err(1, "calloc");

	ca->caname = strdup(caname);
	snprintf(ca->sslpath, sizeof(ca->sslpath), SSLDIR "/%s", caname);
	strlcpy(ca->passfile, ca->sslpath, sizeof(ca->passfile));
	strlcat(ca->passfile, "/ikeca.passwd", sizeof(ca->passfile));

	if (quiet)
		strlcpy(ca->batch, "-batch ", sizeof(ca->batch));

	if (create == 0 && stat(ca->sslpath, &st) == -1) {
		free(ca->caname);
		free(ca);
		errx(1, "CA '%s' does not exist", caname);
	}

	if (mkdir(ca->sslpath, 0777) == -1 && errno != EEXIST)
		err(1, "failed to create dir %s", ca->sslpath);
	snprintf(path, sizeof(path), "%s/private", ca->sslpath);
	if (mkdir(path, 0700) == -1 && errno != EEXIST)
		err(1, "failed to create dir %s", path);
	snprintf(path, sizeof(path), "%s/intermediates", ca->sslpath);
	if (mkdir(path, 0777) == -1 && errno != EEXIST)
		err(1, "failed to create dir %s", path);

	if (create && stat(ca->passfile, &st) == -1 && errno == ENOENT)
		ca_newpass(ca->passfile, pass);

	return (ca);
}

/*
 * Return CA object for issuing CA, or NULL otherwise.
 */
static struct ca *
ca_issuer(struct ca *subca)
{
	struct stat	 st;
	char		 issuer[PATH_MAX];
	char		 sslpath[PATH_MAX];
	struct ca	*ca;
	char		*caname;

	snprintf(issuer, sizeof(issuer), "%s/issuer", subca->sslpath);
	if (lstat(issuer, &st) == -1)
		return (NULL);
	if (!S_ISLNK(st.st_mode)) {
		printf("issuer for CA '%s' is not a symlink\n",
		    subca->caname);
		return (NULL);
	}
	memset(sslpath, 0, sizeof(sslpath));
	if (readlink(issuer, sslpath, sizeof(sslpath)) == -1) {
		printf("unable to read issuer symlink for CA '%s'\n",
		    subca->caname);
		return (NULL);
	}

	/* Create CA object */
	ca = calloc(1, sizeof(struct ca));
	if (ca == NULL)
		err(1, "calloc");

	strlcpy(ca->sslpath, sslpath, sizeof(ca->sslpath));
	snprintf(ca->passfile, sizeof(ca->passfile), "%s/ikeca.passwd",
	    sslpath);

	caname = strrchr(sslpath, '/');
	if (caname == NULL || caname[0] == '\0')
		err(1, "strrchr");
	ca->caname = strdup(caname + 1);
	return (ca);
}

int
ca_subca_create(struct ca *ca, char *caname, char *password, int quiet)
{
	struct ca	*subca;
	char		 cmd[PATH_MAX * 2];

	subca = ca_setup(caname, 1, quiet, password);

	/* Chain CAs */
	snprintf(cmd, sizeof(cmd), "ln -sf %s %s/issuer", ca->sslpath,
	    subca->sslpath);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "ln -sf %s %s/intermediates/%s",
	    subca->sslpath, ca->sslpath, subca->caname);
	system(cmd);

	return (ca_create_internal(subca, ca));
}

int
ca_subca_revoke(struct ca *ca, char *caname)
{
	char		 buf1[PATH_MAX];
	char		 buf2[PATH_MAX];

	snprintf(buf1, sizeof(buf1), "%s/intermediates/%s", ca->sslpath,
	    caname);
	memset(buf2, 0, sizeof(buf2));
	if (readlink(buf1, buf2, sizeof(buf2)) == -1) {
		printf("Intermediate symlink for CA '%s' broken\n", caname);
		return (1);
	}
	snprintf(buf1, sizeof(buf1), "%s/%s-ca.crt", buf2, caname);
	return (ca_revoke_internal(ca, buf1));
}
