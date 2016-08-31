/*	$OpenBSD: config.c,v 1.42 2016/06/01 11:16:41 patrick Exp $	*/

/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <event.h>

#include "defines.h"
#include "iked.h"
#include "ikev2.h"

void
config_init(struct iked_config *config)
{

	memset(config, 0, sizeof(*config));
	RB_INIT(&config->cfg_users);
	TAILQ_INIT(&config->cfg_policies);
}

void
config_cleanup(struct iked_config *config)
{
	struct iked_policy	*pol;
	struct iked_user	*usr;

	while ((pol = TAILQ_FIRST(&config->cfg_policies)) != NULL) {
		TAILQ_REMOVE(&config->cfg_policies, pol, pol_entry);
		config_free_flows(&pol->pol_flows);
		config_free_proposals(&pol->pol_proposals, 0);
		free(pol);
	}
	config->cfg_defpolicy = NULL;

	while ((usr = RB_MIN(iked_users, &config->cfg_users)) != NULL) {
		RB_REMOVE(iked_users, &config->cfg_users, usr);
		free(usr);
	}

	if (config->cfg_ocsp_url != NULL) {
		free(config->cfg_ocsp_url);
		config->cfg_ocsp_url = NULL;
	}
}

void
config_replace(struct iked *env, struct iked_config *new)
{
	struct iked_config	*cur = &env->sc_config;
	struct iked_flow	*flow, *flowkey;
	struct iked_sa		*sa, *satmp;
	struct iked_policy	*pol, *polkey;
	struct iked_user	*usr;

	/*
	 * Walk current policies and transfer state to new policies
	 */
	TAILQ_FOREACH(polkey, &cur->cfg_policies, pol_entry) {
		pol = policy_test(&new->cfg_policies, polkey, 0);
		TAILQ_FOREACH_SAFE(sa, &polkey->pol_sapeers, sa_peer_entry,
		    satmp) {
			if (pol != NULL) {
				TAILQ_REMOVE(&polkey->pol_sapeers, sa,
				    sa_peer_entry);
				sa->sa_policy = pol;
				TAILQ_INSERT_TAIL(&pol->pol_sapeers, sa,
				    sa_peer_entry);
			} else
				sa_free(env, sa);
		}
		RB_FOREACH(flowkey, iked_flows, &polkey->pol_flows) {
			if (!flowkey->flow_loaded)
				continue;
			flow = (pol == NULL) ? NULL :
			    policy_find_flow(pol, flowkey, 0);
			if (flow != NULL) {
				flow->flow_loaded = 1;
				flowkey->flow_loaded = 0;
			} else
				pfkey_flow_delete(env->sc_pfkey, flowkey);
		}
	}

	config_cleanup(cur);

	memcpy(cur, new, sizeof(*cur));
	RB_INIT(&cur->cfg_users);
	TAILQ_INIT(&cur->cfg_policies);
	new->cfg_ocsp_url = NULL;
	new->cfg_defpolicy = NULL;

	while ((pol = TAILQ_FIRST(&new->cfg_policies)) != NULL) {
		TAILQ_REMOVE(&new->cfg_policies, pol, pol_entry);
		TAILQ_INSERT_TAIL(&cur->cfg_policies, pol, pol_entry);
	}
	while ((usr = RB_MIN(iked_users, &new->cfg_users)) != NULL) {
		RB_REMOVE(iked_users, &new->cfg_users, usr);
		RB_INSERT(iked_users, &cur->cfg_users, usr);
	}
}

struct iked_sa *
config_new_sa(struct iked *env, int initiator)
{
	struct iked_sa	*sa;

	if ((sa = calloc(1, sizeof(*sa))) == NULL)
		return (NULL);

	TAILQ_INIT(&sa->sa_proposals);
	TAILQ_INIT(&sa->sa_childsas);
	TAILQ_INIT(&sa->sa_flows);
	TAILQ_INIT(&sa->sa_requests);
	TAILQ_INIT(&sa->sa_responses);
	sa->sa_hdr.sh_initiator = initiator;
	sa->sa_type = IKED_SATYPE_LOCAL;

	if (initiator)
		sa->sa_hdr.sh_ispi = config_getspi();
	else
		sa->sa_hdr.sh_rspi = config_getspi();

	gettimeofday(&sa->sa_timecreated, NULL);
	memcpy(&sa->sa_timeused, &sa->sa_timecreated, sizeof(sa->sa_timeused));

	return (sa);
}

uint64_t
config_getspi(void)
{
	uint64_t	 spi;

	do {
		arc4random_buf(&spi, sizeof spi);
	} while (spi == 0);

	return (spi);
}

void
config_free_kex(struct iked_kex *kex)
{
	if (kex == NULL)
		return;

	ibuf_release(kex->kex_inonce);
	ibuf_release(kex->kex_rnonce);

	if (kex->kex_dhgroup != NULL)
		group_free(kex->kex_dhgroup);
	ibuf_release(kex->kex_dhiexchange);
	ibuf_release(kex->kex_dhrexchange);

	free(kex);
}

void
config_free_sa(struct iked *env, struct iked_sa *sa)
{
	timer_del(env, &sa->sa_timer);
	timer_del(env, &sa->sa_rekey);

	config_free_proposals(&sa->sa_proposals, 0);
	config_free_childsas(env, &sa->sa_childsas, NULL, NULL);
	sa_free_flows(env, &sa->sa_flows);

	if (sa->sa_addrpool) {
		(void)RB_REMOVE(iked_addrpool, &env->sc_addrpool, sa);
		free(sa->sa_addrpool);
	}
	if (sa->sa_addrpool6) {
		(void)RB_REMOVE(iked_addrpool6, &env->sc_addrpool6, sa);
		free(sa->sa_addrpool6);
	}

	if (sa->sa_policy) {
		TAILQ_REMOVE(&sa->sa_policy->pol_sapeers, sa, sa_peer_entry);
		policy_unref(env, sa->sa_policy);
	}

	ikev2_msg_flushqueue(env, &sa->sa_requests);
	ikev2_msg_flushqueue(env, &sa->sa_responses);

	ibuf_release(sa->sa_inonce);
	ibuf_release(sa->sa_rnonce);

	if (sa->sa_dhgroup != NULL)
		group_free(sa->sa_dhgroup);
	ibuf_release(sa->sa_dhiexchange);
	ibuf_release(sa->sa_dhrexchange);

	hash_free(sa->sa_prf);
	hash_free(sa->sa_integr);
	cipher_free(sa->sa_encr);

	ibuf_release(sa->sa_key_d);
	ibuf_release(sa->sa_key_iauth);
	ibuf_release(sa->sa_key_rauth);
	ibuf_release(sa->sa_key_iencr);
	ibuf_release(sa->sa_key_rencr);
	ibuf_release(sa->sa_key_iprf);
	ibuf_release(sa->sa_key_rprf);

	ibuf_release(sa->sa_1stmsg);
	ibuf_release(sa->sa_2ndmsg);

	ibuf_release(sa->sa_iid.id_buf);
	ibuf_release(sa->sa_rid.id_buf);
	ibuf_release(sa->sa_icert.id_buf);
	ibuf_release(sa->sa_rcert.id_buf);

	ibuf_release(sa->sa_eap.id_buf);
	free(sa->sa_eapid);
	ibuf_release(sa->sa_eapmsk);

	free(sa);
}

struct iked_policy *
config_new_policy(struct iked *env)
{
	struct iked_policy	*pol;

	if ((pol = calloc(1, sizeof(*pol))) == NULL)
		return (NULL);

	/* XXX caller does this again */
	TAILQ_INIT(&pol->pol_proposals);
	TAILQ_INIT(&pol->pol_sapeers);
	RB_INIT(&pol->pol_flows);

	return (pol);
}

void
config_free_policy(struct iked *env, struct iked_policy *pol)
{
	struct iked_sa		*sa;

	if (pol->pol_flags & IKED_POLICY_REFCNT)
		goto remove;

	TAILQ_REMOVE(&env->sc_config.cfg_policies, pol, pol_entry);

	TAILQ_FOREACH(sa, &pol->pol_sapeers, sa_peer_entry) {
		/* Remove from the policy list, but keep for existing SAs */
		if (sa->sa_policy == pol)
			policy_ref(env, pol);
		else
			log_warnx("%s: ERROR: sa_policy %p != pol %p",
			    __func__, sa->sa_policy, pol);
	}

	if (pol->pol_refcnt)
		return;

 remove:
	config_free_proposals(&pol->pol_proposals, 0);
	config_free_flows(&pol->pol_flows);
	free(pol);
}

struct iked_proposal *
config_add_proposal(struct iked_proposals *head, unsigned int id,
    unsigned int proto)
{
	struct iked_proposal	*pp;

	TAILQ_FOREACH(pp, head, prop_entry) {
		if (pp->prop_protoid == proto &&
		    pp->prop_id == id)
			return (pp);
	}

	if ((pp = calloc(1, sizeof(*pp))) == NULL)
		return (NULL);

	pp->prop_protoid = proto;
	pp->prop_id = id;

	TAILQ_INSERT_TAIL(head, pp, prop_entry);

	return (pp);
}

void
config_free_proposals(struct iked_proposals *head, unsigned int proto)
{
	struct iked_proposal	*prop, *next;

	for (prop = TAILQ_FIRST(head); prop != NULL; prop = next) {
		next = TAILQ_NEXT(prop, prop_entry);

		/* Free any proposal or only selected SA proto */
		if (proto != 0 && prop->prop_protoid != proto)
			continue;

		log_debug("%s: free %p", __func__, prop);

		TAILQ_REMOVE(head, prop, prop_entry);
		if (prop->prop_nxforms)
			free(prop->prop_xforms);
		free(prop);
	}
}

void
config_free_flows(struct iked_flows *head)
{
	struct iked_flow	*flow, *next;

	for (flow = RB_MIN(iked_flows, head); flow != NULL; flow = next) {
		next = RB_NEXT(iked_flows, head, flow);
		log_debug("%s: free %p", __func__, flow);
		RB_REMOVE(iked_flows, head, flow);
		flow_free(flow);
	}
}

void
config_free_childsas(struct iked *env, struct iked_childsas *head,
    struct iked_spi *peerspi, struct iked_spi *localspi)
{
	struct iked_childsa	*csa, *nextcsa;

	if (localspi != NULL)
		bzero(localspi, sizeof(*localspi));

	for (csa = TAILQ_FIRST(head); csa != NULL; csa = nextcsa) {
		nextcsa = TAILQ_NEXT(csa, csa_entry);

		if (peerspi != NULL) {
			/* Only delete matching peer SPIs */
			if (peerspi->spi != csa->csa_peerspi)
				continue;

			/* Store assigned local SPI */
			if (localspi != NULL && localspi->spi == 0)
				memcpy(localspi, &csa->csa_spi,
				    sizeof(*localspi));
		}
		log_debug("%s: free %p", __func__, csa);

		TAILQ_REMOVE(head, csa, csa_entry);
		if (csa->csa_loaded) {
			RB_REMOVE(iked_activesas, &env->sc_activesas, csa);
			(void)pfkey_sa_delete(env->sc_pfkey, csa);
		}
		childsa_free(csa);
	}
}

struct iked_transform *
config_add_transform(struct iked_proposal *prop, unsigned int type,
    unsigned int id, unsigned int length, unsigned int keylength)
{
	struct iked_transform	*xform;
	struct iked_constmap	*map = NULL;
	int			 score = 1;
	unsigned int		 i;

	switch (type) {
	case IKEV2_XFORMTYPE_ENCR:
		map = ikev2_xformencr_map;
		break;
	case IKEV2_XFORMTYPE_PRF:
		map = ikev2_xformprf_map;
		break;
	case IKEV2_XFORMTYPE_INTEGR:
		map = ikev2_xformauth_map;
		break;
	case IKEV2_XFORMTYPE_DH:
		map = ikev2_xformdh_map;
		break;
	case IKEV2_XFORMTYPE_ESN:
		map = ikev2_xformesn_map;
		break;
	default:
		log_debug("%s: invalid transform type %d", __func__, type);
		return (NULL);
	}

	for (i = 0; i < prop->prop_nxforms; i++) {
		xform = prop->prop_xforms + i;
		if (xform->xform_type == type &&
		    xform->xform_id == id &&
		    xform->xform_length == length)
			return (xform);
	}

	for (i = 0; i < prop->prop_nxforms; i++) {
		xform = prop->prop_xforms + i;
		if (xform->xform_type == type) {
			switch (type) {
			case IKEV2_XFORMTYPE_ENCR:
			case IKEV2_XFORMTYPE_INTEGR:
				score += 3;
				break;
			case IKEV2_XFORMTYPE_DH:
				score += 2;
				break;
			default:
				score += 1;
				break;
			}
		}
	}

	if ((xform = reallocarray(prop->prop_xforms,
	    prop->prop_nxforms + 1, sizeof(*xform))) == NULL) {
		return (NULL);
	}

	prop->prop_xforms = xform;
	xform = prop->prop_xforms + prop->prop_nxforms++;
	bzero(xform, sizeof(*xform));

	xform->xform_type = type;
	xform->xform_id = id;
	xform->xform_length = length;
	xform->xform_keylength = keylength;
	xform->xform_score = score;
	xform->xform_map = map;

	return (xform);
}

struct iked_transform *
config_findtransform(struct iked_proposals *props, uint8_t type,
    unsigned int proto)
{
	struct iked_proposal	*prop;
	struct iked_transform	*xform;
	unsigned int		 i;

	/* Search of the first transform with the desired type */
	TAILQ_FOREACH(prop, props, prop_entry) {
		/* Find any proposal or only selected SA proto */
		if (proto != 0 && prop->prop_protoid != proto)
			continue;
		for (i = 0; i < prop->prop_nxforms; i++) {
			xform = prop->prop_xforms + i;
			if (xform->xform_type == type)
				return (xform);
		}
	}

	return (NULL);
}

/*
 * Inter-process communication of configuration items.
 */

int
config_setcoupled(struct iked *env, unsigned int couple)
{
	unsigned int	 type;

	type = couple ? IMSG_CTL_COUPLE : IMSG_CTL_DECOUPLE;
	return (proc_compose(&env->sc_ps, PROC_IKEV2, type, NULL, 0));
}

int
config_getcoupled(struct iked *env, unsigned int type)
{
	return (pfkey_couple(env->sc_pfkey, &env->sc_sas,
	    type == IMSG_CTL_COUPLE ? 1 : 0));
}

int
config_setmode(struct iked *env, unsigned int passive)
{
	unsigned int	 type;

	type = passive ? IMSG_CTL_PASSIVE : IMSG_CTL_ACTIVE;
	return (proc_compose(&env->sc_ps, PROC_IKEV2, type, NULL, 0));
}

int
config_getmode(struct iked *env, unsigned int type)
{
	uint8_t		 old;
	unsigned char	*mode[] = { "active", "passive" };

	old = env->sc_config.cfg_passive ? 1 : 0;
	env->sc_config.cfg_passive = (type == IMSG_CTL_PASSIVE) ? 1 : 0;

	if (old == env->sc_config.cfg_passive)
		return (0);

	log_debug("%s: mode %s -> %s", __func__, mode[old],
	    mode[env->sc_config.cfg_passive]);

	return (0);
}

int
config_setreset(struct iked *env, unsigned int mode, enum privsep_procid id)
{

	return (proc_compose(&env->sc_ps, id, IMSG_CTL_RESET, &mode,
	    sizeof(mode)));
}

int
config_getreset(struct iked *env, struct imsg *imsg)
{
	struct iked_policy	*pol, *nextpol;
	struct iked_sa		*sa, *nextsa;
	struct iked_user	*usr, *nextusr;
	unsigned int		 mode;

	IMSG_SIZE_CHECK(imsg, &mode);
	memcpy(&mode, imsg->data, sizeof(mode));

	if (mode == RESET_ALL || mode == RESET_POLICY) {
		log_debug("%s: flushing policies", __func__);
		for (pol = TAILQ_FIRST(&env->sc_config.cfg_policies);
		    pol != NULL; pol = nextpol) {
			nextpol = TAILQ_NEXT(pol, pol_entry);
			config_free_policy(env, pol);
		}
	}

	if (mode == RESET_ALL || mode == RESET_SA) {
		log_debug("%s: flushing SAs", __func__);
		for (sa = RB_MIN(iked_sas, &env->sc_sas);
		    sa != NULL; sa = nextsa) {
			nextsa = RB_NEXT(iked_sas, &env->sc_sas, sa);
			RB_REMOVE(iked_sas, &env->sc_sas, sa);
			config_free_sa(env, sa);
		}
	}

	if (mode == RESET_ALL || mode == RESET_USER) {
		log_debug("%s: flushing users", __func__);
		for (usr = RB_MIN(iked_users, &env->sc_config.cfg_users);
		    usr != NULL; usr = nextusr) {
			nextusr = RB_NEXT(iked_users,
			    &env->sc_config.cfg_users, usr);
			RB_REMOVE(iked_users, &env->sc_config.cfg_users, usr);
			free(usr);
		}
	}

	return (0);
}

int
config_setsocket(struct iked *env, struct sockaddr_storage *ss,
    in_port_t port, enum privsep_procid id)
{
	int	 s;

	s = udp_bind((struct sockaddr *)ss, port);
	if (s == -1)
		return (-1);
	return(proc_compose_imsg(&env->sc_ps, id, -1, IMSG_UDP_SOCKET, -1,
	    s, ss, sizeof(*ss)));
}

int
config_getsocket(struct iked *env, struct imsg *imsg,
    void (*cb)(int, short, void *))
{
	struct iked_socket	*sock, **sptr, **nptr;

	log_debug("%s: received socket fd %d", __func__, imsg->fd);

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatal("config_getsocket: calloc");

	IMSG_SIZE_CHECK(imsg, &sock->sock_addr);

	memcpy(&sock->sock_addr, imsg->data, sizeof(sock->sock_addr));
	sock->sock_fd = imsg->fd;
	sock->sock_env = env;

	switch (sock->sock_addr.ss_family) {
	case AF_INET:
		sptr = &env->sc_sock4[0];
		nptr = &env->sc_sock4[1];
		break;
	case AF_INET6:
		sptr = &env->sc_sock6[0];
		nptr = &env->sc_sock6[1];
		break;
	default:
		fatal("config_getsocket: socket af");
		/* NOTREACHED */
	}
	if (*sptr == NULL)
		*sptr = sock;
	if (*nptr == NULL &&
	    socket_getport((struct sockaddr *)&sock->sock_addr) ==
	    IKED_NATT_PORT)
		*nptr = sock;

	event_set(&sock->sock_ev, sock->sock_fd,
	    EV_READ|EV_PERSIST, cb, sock);
	event_add(&sock->sock_ev, NULL);

	return (0);
}

int
config_setpfkey(struct iked *env, enum privsep_procid id)
{
	int	 s;

	s = pfkey_socket();
	if (s == -1)
		return (-1);
	return (proc_compose_imsg(&env->sc_ps, id, -1, IMSG_PFKEY_SOCKET, -1,
	    s, NULL, 0));
}

int
config_getpfkey(struct iked *env, struct imsg *imsg)
{
	log_debug("%s: received pfkey fd %d", __func__, imsg->fd);
	pfkey_init(env, imsg->fd);
	return (0);
}

int
config_setuser(struct iked *env, struct iked_user *usr)
{

	print_user(usr);

	return (proc_compose(&env->sc_ps, PROC_IKEV2, IMSG_CFG_USER, usr,
	    sizeof(*usr)));
}

int
config_getuser(struct iked *env, struct imsg *imsg)
{
	struct iked_user	*usr;

	IMSG_SIZE_CHECK(imsg, usr);

	usr = malloc(sizeof(*usr));
	if (usr == NULL)
		return (-1);

	memcpy(usr, imsg->data, sizeof(*usr));

	RB_INSERT(iked_users, &env->sc_newconfig.cfg_users, usr);
	env->sc_newconfig.cfg_nusers++;
	return (0);
}

int
config_setpolicy(struct iked *env, struct iked_policy *pol)
{
	struct iked_proposal	*prop;
	struct iked_flow	*flow;
	struct iked_transform	*xform;
	size_t			 size, iovcnt, j, c = 0;
	struct iovec		 iov[IOV_MAX];

	iovcnt = 1;
	size = sizeof(*pol);
	TAILQ_FOREACH(prop, &pol->pol_proposals, prop_entry) {
		size += (prop->prop_nxforms * sizeof(*xform)) +
		    (sizeof(*prop));
		iovcnt += prop->prop_nxforms + 1;
	}

	iovcnt += pol->pol_nflows;

	if (iovcnt > IOV_MAX) {
		log_warn("%s: too many proposals/flows", __func__);
		return (-1);
	}

	iov[c].iov_base = pol;
	iov[c++].iov_len = sizeof(*pol);

	TAILQ_FOREACH(prop, &pol->pol_proposals, prop_entry) {
		iov[c].iov_base = prop;
		iov[c++].iov_len = sizeof(*prop);

		for (j = 0; j < prop->prop_nxforms; j++) {
			xform = prop->prop_xforms + j;

			iov[c].iov_base = xform;
			iov[c++].iov_len = sizeof(*xform);
		}
	}

	RB_FOREACH(flow, iked_flows, &pol->pol_flows) {
		iov[c].iov_base = flow;
		iov[c++].iov_len = sizeof(*flow);
	}

	print_policy(pol);

	return (proc_composev(&env->sc_ps, PROC_IKEV2, IMSG_CFG_POLICY,
	    iov, iovcnt));
}

int
config_getpolicy(struct iked *env, struct imsg *imsg)
{
	struct iked_policy	*pol;
	struct iked_proposal	 pp, *prop;
	struct iked_transform	 xf, *xform;
	struct iked_flow	*flow;
	off_t			 offset = 0;
	unsigned int		 i, j;
	uint8_t			*buf = (uint8_t *)imsg->data;

	IMSG_SIZE_CHECK(imsg, pol);
	log_debug("%s: received policy", __func__);

	if ((pol = config_new_policy(NULL)) == NULL)
		fatal("config_getpolicy: new policy");

	memcpy(pol, buf, sizeof(*pol));
	offset += sizeof(*pol);

	TAILQ_INIT(&pol->pol_proposals);
	TAILQ_INIT(&pol->pol_sapeers);
	RB_INIT(&pol->pol_flows);

	for (i = 0; i < pol->pol_nproposals; i++) {
		memcpy(&pp, buf + offset, sizeof(pp));
		offset += sizeof(pp);

		if ((prop = config_add_proposal(&pol->pol_proposals,
		    pp.prop_id, pp.prop_protoid)) == NULL)
			fatal("config_getpolicy: add proposal");

		for (j = 0; j < pp.prop_nxforms; j++) {
			memcpy(&xf, buf + offset, sizeof(xf));
			offset += sizeof(xf);

			if ((xform = config_add_transform(prop, xf.xform_type,
			    xf.xform_id, xf.xform_length,
			    xf.xform_keylength)) == NULL)
				fatal("config_getpolicy: add transform");
		}
	}

	for (i = 0; i < pol->pol_nflows; i++) {
		if ((flow = calloc(1, sizeof(*flow))) == NULL)
			fatal("config_getpolicy: new flow");

		memcpy(flow, buf + offset, sizeof(*flow));
		offset += sizeof(*flow);

		if (RB_INSERT(iked_flows, &pol->pol_flows, flow))
			free(flow);
	}

	TAILQ_INSERT_TAIL(&env->sc_newconfig.cfg_policies, pol, pol_entry);
	env->sc_newconfig.cfg_npolicies++;

	if (pol->pol_flags & IKED_POLICY_DEFAULT)
		env->sc_newconfig.cfg_defpolicy = pol;
	return (0);
}

int
config_setocsp(struct iked *env, char *url)
{

	return (proc_compose(&env->sc_ps, PROC_CERT, IMSG_OCSP_URL,
	    url, (url != NULL) ? strlen(url) : 0));
}

int
config_getocsp(struct iked *env, struct imsg *imsg)
{

	free(env->sc_config.cfg_ocsp_url);
	if (IMSG_DATA_SIZE(imsg) > 0)
		env->sc_config.cfg_ocsp_url = get_string(imsg->data,
		    IMSG_DATA_SIZE(imsg));
	else
		env->sc_config.cfg_ocsp_url = NULL;
	log_debug("%s: ocsp_url %s", __func__,
	    (env->sc_config.cfg_ocsp_url != NULL)
	    ? env->sc_config.cfg_ocsp_url : "none");
	return (0);
}

int
config_setapply(struct iked *env, enum apply_action action)
{

	log_debug("%s: action=%u", __func__, action);
	return (proc_compose(&env->sc_ps, PROC_IKEV2, IMSG_CFG_APPLY,
	    &action, sizeof(action)));
}

int
config_getapply(struct iked *env, struct imsg *imsg)
{
	enum apply_action	 action;

	action = *(enum apply_action *)(imsg->data);
	log_debug("%s: action=%u", __func__, action);
	switch (action) {
	case APPLY_BEGIN:
		config_init(&env->sc_newconfig);
		break;
	case APPLY_ABORT:
		config_cleanup(&env->sc_newconfig);
		break;
	case APPLY_COMPLETE:
		policy_calc_skip_steps(&env->sc_newconfig.cfg_policies);
		config_replace(env, &env->sc_newconfig);
		break;
	}
	return (0);
}

int
config_apply(struct iked *env, struct iked_config *config)
{
	struct iked_policy	*pol;
	struct iked_user	*usr;
	int			 err;

	err = config_setapply(env, APPLY_BEGIN);
	if (err)
		return (err);

	do {
		err = config_setocsp(env, config->cfg_ocsp_url);
		if (err)
			break;

		TAILQ_FOREACH(pol, &config->cfg_policies, pol_entry) {
			err = config_setpolicy(env, pol);
			if (err)
				break;
		}
		if (err)
			break;

		usr = RB_MIN(iked_users, &config->cfg_users);
		while (usr != NULL) {
			err = config_setuser(env, usr);
			if (err)
				break;
			usr = RB_NEXT(iked_users, &config->cfg_users, usr);
		}
		if (err)
			break;

		err = config_setapply(env, APPLY_COMPLETE);
	} while (0);

	if (err) {
		config_setapply(env, APPLY_ABORT);
		config_cleanup(config);
		return (err);
	}

	err = config_setcoupled(env, config->cfg_decoupled ? 0 : 1);
	if (!err) {
		env->sc_config.cfg_decoupled = config->cfg_decoupled;
		err = config_setmode(env, config->cfg_passive ? 1 : 0);
		if (!err)
			env->sc_config.cfg_passive = config->cfg_passive;
	}

	config_cleanup(config);

	return (err);
}
