/*	$OpenBSD: iked.c,v 1.31 2016/09/04 16:55:43 reyk Exp $	*/

/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2016 Marcel Moolenaar <marcel@brkt.com>
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

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>

#include <event2/event.h>

#include "iked.h"
#include "ikev2.h"

__dead void usage(void);

void	 parent_sig_handler(int, short, void *);
int	 parent_dispatch_ca(int, struct privsep_proc *, struct imsg *);
int	 parent_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 parent_configure(struct iked *, struct iked_config *);

static struct privsep_proc procs[] = {
	{ "ca",		PROC_CERT,	parent_dispatch_ca, caproc, IKED_CA },
	{ "control",	PROC_CONTROL,	parent_dispatch_control, control },
	{ "ikev2",	PROC_IKEV2,	NULL, ikev2 }
};

static struct {
	const char *name;
	int val;
} log_facilities[] = {
	{ "daemon",	LOG_DAEMON },
	{ "user",	LOG_USER },
	{ "auth",	LOG_AUTH },
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV },
#endif
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL,		-1 }
};

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-6dnSTtv] [-D macro=value] "
	    "[-f file]\n", __progname);
	exit(1);
}

static void
parse_facility(const char *facility, int *result)
{
	unsigned int idx;

	idx = 0;
	while (log_facilities[idx].name != NULL) {
		if (strcasecmp(facility, log_facilities[idx].name) == 0) {
			*result = log_facilities[idx].val;
			return;
		}
		idx++;
	}
	log_warnx("%s: syslog facility unknown or invalid", facility);
}

int
main(int argc, char *argv[], char *envp[])
{
	struct iked_config	*config;
	struct iked		*env;
	const char		*conffile;
	struct privsep		*ps;
	unsigned int		 opts;
	int			 c, debug, facility, verbose;

	conffile = IKED_CONFIG;
	debug = 0;
	facility = LOG_DAEMON;
	opts = 0;
	verbose = 0;

	log_init(1, LOG_DAEMON);

	while ((c = getopt(argc, argv, "6D:L:STdf:ntv")) != -1) {
		switch (c) {
		case '6':
			opts |= IKED_OPT_NOIPV6BLOCKING;
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'L':
			parse_facility(optarg, &facility);
			break;
		case 'S':
			opts |= IKED_OPT_PASSIVE;
			break;
		case 'T':
			opts |= IKED_OPT_NONATT;
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			debug = 1;
			opts |= IKED_OPT_NOACTION;
			break;
		case 't':
			opts |= IKED_OPT_NATT;
			break;
		case 'v':
			verbose++;
			opts |= IKED_OPT_VERBOSE;
			break;
		default:
			usage();
		}
	}

	if (opts & IKED_OPT_NOACTION) {
		config = parse_config(conffile, opts);
		if (config != NULL) {
			fprintf(stderr, "configuration OK\n");
			exit(0);
		}
		exit(1);
	}

	env = calloc(1, sizeof(*env));
	if (env == NULL)
		fatal("calloc: env");

	env->sc_opts = opts;

	ps = &env->sc_ps;
	ps->ps_env = env;
	TAILQ_INIT(&ps->ps_rcsocks);

	if ((opts & (IKED_OPT_NONATT|IKED_OPT_NATT)) ==
	    (IKED_OPT_NONATT|IKED_OPT_NATT))
		errx(1, "conflicting NAT-T options");

	if (strlcpy(env->sc_conffile, conffile, PATH_MAX) >= PATH_MAX)
		errx(1, "config file exceeds PATH_MAX");

	config_init(&env->sc_config);
	ca_sslinit();
	policy_init(env);

	/* check for root privileges */
	if (geteuid())
		errx(1, "need root privileges");

	if ((ps->ps_pw =  getpwnam(IKED_USER)) == NULL)
		errx(1, "unknown user %s", IKED_USER);

	/* Configure the control socket */
	ps->ps_csock.cs_name = IKED_SOCKET;

	log_init(debug, facility);
	log_verbose(verbose);

	if (!debug && daemon(0, 0) == -1)
		err(1, "failed to daemonize");

	group_init();

	ps->ps_ninstances = 1;
	proc_init(ps, procs, nitems(procs));

	setproctitle("parent");
	log_procinit("parent");

	env->sc_evbase = event_base_new();

	ps->ps_evsigint = evsignal_new(env->sc_evbase, SIGINT,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsigint, NULL);
	ps->ps_evsigterm = evsignal_new(env->sc_evbase, SIGTERM,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsigterm, NULL);
	ps->ps_evsigchld = evsignal_new(env->sc_evbase, SIGCHLD,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsigchld, NULL);
	ps->ps_evsighup = evsignal_new(env->sc_evbase, SIGHUP,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsighup, NULL);
	ps->ps_evsigpipe = evsignal_new(env->sc_evbase, SIGPIPE,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsigpipe, NULL);
	ps->ps_evsigusr1 = evsignal_new(env->sc_evbase, SIGUSR1,
	    parent_sig_handler, ps);
	evsignal_add(ps->ps_evsigusr1, NULL);

	proc_listen(ps, procs, nitems(procs));

	config = parse_config(env->sc_conffile, env->sc_opts);
	if (config == NULL) {
		proc_close(&env->sc_ps);
		proc_kill(&env->sc_ps);
		exit(1);
	}
	if (parent_configure(env, config) == -1)
		fatalx("configuration failed");

	event_base_dispatch(env->sc_evbase);

	proc_close(&env->sc_ps);
	proc_kill(&env->sc_ps);

	if (env->sc_ps.ps_restart) {
		log_warnx("%s[%d] restarting",
		    env->sc_ps.ps_title[PROC_PARENT],
		    env->sc_ps.ps_pid[PROC_PARENT]);
		execve(argv[0], argv, envp);
		log_warnx("unable to restart -- terminating");
		exit(1);
	}

	log_info("%s[%d] terminating", env->sc_ps.ps_title[PROC_PARENT],
	    env->sc_ps.ps_pid[PROC_PARENT]);

	return (0);
}

int
parent_configure(struct iked *env, struct iked_config *config)
{
	struct sockaddr_storage	  ss;

	env->sc_pfkey = -1;
	config_setpfkey(env, PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET;
	SET_SS_LEN(&ss, sizeof(struct sockaddr_in));

	if ((env->sc_opts & IKED_OPT_NATT) == 0)
		config_setsocket(env, &ss, ntohs(IKED_IKE_PORT), PROC_IKEV2);
	if ((env->sc_opts & IKED_OPT_NONATT) == 0)
		config_setsocket(env, &ss, ntohs(IKED_NATT_PORT), PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET6;
	SET_SS_LEN(&ss, sizeof(struct sockaddr_in6));

	if ((env->sc_opts & IKED_OPT_NATT) == 0)
		config_setsocket(env, &ss, ntohs(IKED_IKE_PORT), PROC_IKEV2);
	if ((env->sc_opts & IKED_OPT_NONATT) == 0)
		config_setsocket(env, &ss, ntohs(IKED_NATT_PORT), PROC_IKEV2);

	/*
	 * pledge in the parent process:
	 * It has to run fairly late to allow forking the processes and
	 * opening the PFKEY socket and the listening UDP sockets (once)
	 * that need the bypass ioctls that are never allowed by pledge.
	 *
	 * Other flags:
	 * stdio - for malloc and basic I/O including events.
	 * rpath - for reload to open and read the configuration files.
	 * proc - run kill to terminate its children safely.
	 * dns - for reload and ocsp connect.
	 * inet - for ocsp connect.
	 * route - for using interfaces in iked.conf (SIOCGIFGMEMB)
	 * sendfd - for ocsp sockets.
	 * exec - for using execve to restart.
	 */
	if (pledge("stdio rpath proc dns inet route sendfd exec", NULL) == -1)
		fatal("pledge");

	return (config_apply(env, config));
}

void
parent_reload(struct iked *env, int reset, const char *filename)
{
	struct iked_config	*config;

	/* Switch back to the default config file */
	if (filename == NULL || *filename == '\0')
		filename = env->sc_conffile;

	log_debug("%s: level %d config file %s", __func__, reset, filename);

	config_setreset(env, reset, PROC_IKEV2);
	config_setreset(env, reset, PROC_CERT);

	if (reset != RESET_RELOAD)
		return;

	config = parse_config(filename, env->sc_opts);
	if (config == NULL) {
		log_debug("%s: failed to load config file %s", __func__,
		    filename);
		return;
	}

	config_apply(env, config);
}

void
parent_sig_handler(int sig, short event, void *arg)
{
	struct privsep	*ps = arg;
	int		 die, status;
	pid_t		 pid;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);

		/*
		 * This is safe because libevent uses async signal handlers
		 * that run in the event loop and not in signal context.
		 */
		parent_reload(ps->ps_env, RESET_RELOAD, NULL);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		log_info("%s[%d] received %s", ps->ps_title[PROC_PARENT],
		    ps->ps_pid[PROC_PARENT],
		    (sig == SIGTERM) ? "SIGTERM": "SIGINT");
		event_base_loopexit(ps->ps_env->sc_evbase, NULL);
		break;
	case SIGCHLD:
		die = 0;
		do {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid > 0)
				die |= proc_reap(ps, pid, status);
		} while (pid > 0 || (pid == -1 && errno == EINTR));
		if (die)
			event_base_loopexit(ps->ps_env->sc_evbase, NULL);
		break;
	default:
		fatalx("unexpected signal");
	}
}

int
parent_dispatch_ca(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = p->p_ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_OCSP_FD:
		ocsp_connect(env);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
parent_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = p->p_ps->ps_env;
	int		 v;
	char		*str = NULL;
	unsigned int	 type = imsg->hdr.type;

	switch (type) {
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &v);
		memcpy(&v, imsg->data, sizeof(v));
		parent_reload(env, v, NULL);
		break;
	case IMSG_CTL_COUPLE:
	case IMSG_CTL_DECOUPLE:
	case IMSG_CTL_ACTIVE:
	case IMSG_CTL_PASSIVE:
		proc_compose(&env->sc_ps, PROC_IKEV2, type, NULL, 0);
		break;
	case IMSG_CTL_RELOAD:
		if (IMSG_DATA_SIZE(imsg) > 0)
			str = get_string(imsg->data, IMSG_DATA_SIZE(imsg));
		parent_reload(env, RESET_RELOAD, str);
		free(str);
		break;
	case IMSG_CTL_VERBOSE:
		proc_forward_imsg(&env->sc_ps, imsg, PROC_IKEV2, -1);
		proc_forward_imsg(&env->sc_ps, imsg, PROC_CERT, -1);

		/* return 1 to let proc.c handle it locally */
		return (1);
	default:
		return (-1);
	}

	return (0);
}
