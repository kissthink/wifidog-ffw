/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id: conf.c 1241 2007-06-24 04:13:13Z benoitg $ */
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"

#include "util.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oExternalInterface,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthServer,
	oAuthServHostname,
	oAuthServSSLAvailable,
	oAuthServSSLPort,
	oAuthServHTTPPort,
	oAuthServPath,
	oHTTPDMaxConn,
	oHTTPDName,
	oClientTimeout,
	oCheckInterval,
	oWdctlSocket,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
        oTrustedMACList,
        oOwner,
        oNetwork,
	oLat,
	oLon,
	oProxyPort,
//	oProxyHost,
	oOwnerMACList,
	oNodeName,
	oSmtpServer,
	oIptables
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "daemon",             oDaemon },
	{ "debuglevel",         oDebugLevel },
	{ "externalinterface",  oExternalInterface },
	{ "gatewayid",          oGatewayID },
	{ "gatewayinterface",   oGatewayInterface },
	{ "gatewayaddress",     oGatewayAddress },
	{ "gatewayport",        oGatewayPort },
	{ "authserver",         oAuthServer },
	{ "httpdmaxconn",       oHTTPDMaxConn },
	{ "httpdname",          oHTTPDName },
	{ "clienttimeout",      oClientTimeout },
	{ "checkinterval",      oCheckInterval },
	{ "syslogfacility", 	oSyslogFacility },
	{ "wdctlsocket", 	oWdctlSocket },
	{ "hostname",		oAuthServHostname },
	{ "sslavailable",	oAuthServSSLAvailable },
	{ "sslport",		oAuthServSSLPort },
	{ "httpport",		oAuthServHTTPPort },
	{ "path",		oAuthServPath },
	{ "firewallruleset",	oFirewallRuleSet },
	{ "firewallrule",	oFirewallRule },
	{ "trustedmaclist",	oTrustedMACList },
	{ "ownermaclist",	oOwnerMACList },
	{ "proprietary",        oOwner },
	{ "owner",		oOwner },
	{ "network",            oNetwork },
	{ "lat",                oLat },
	{ "lon",                oLon },
	{ "proxyport",      oProxyPort },
//	{ "proxyhost",      oProxyhost },
	{ "nodename",	   	oNodeName },
	{ "smtpserver",         oSmtpServer },
	{ "iptables",         oIptables },
	{ NULL,                 oBadOption },
};

static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
	config.external_interface = NULL;
	config.gw_id = DEFAULT_GATEWAYID;
	config.gw_interface = NULL;
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.auth_servers = NULL;
	config.httpdname = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.daemon = -1;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.wdctl_sock = safe_strdup(DEFAULT_WDCTL_SOCK);
	config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.rulesets = NULL;
	config.trustedmaclist = NULL;
	config.Owner = NULL;
	config.Network = DEFAULT_NETWORK;
	config.Lat = "0";
	config.Lon = "0";
	config.proxy_port = 0;
	config.ownermaclist = NULL;
	config.NodeName = NULL;
	config.SmtpServer = NULL;
	config.Iptables = DEFAULT_IPTABLES;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", 
			filename, linenum, cp);
	return oBadOption;
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE *file, char *filename, int *linenum)
{
	char		*host = NULL,
			*path = NULL,
			line[MAX_BUF],
			*p1,
			*p2;
	int		http_port,
			ssl_port,
			ssl_available,
			opcode;
	t_auth_serv	*new,
			*tmp;

	/* Defaults */
	path = safe_strdup(DEFAULT_AUTHSERVPATH);
	http_port = DEFAULT_AUTHSERVPORT;
	ssl_port = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;
	
	/* Read first line */	
	memset(line, 0, MAX_BUF);
	fgets(line, MAX_BUF - 1, file);
	(*linenum)++; /* increment line counter. */

	/* Parsing loop */
	while ((line[0] != '\0') && (strchr(line, '}') == NULL)) {
		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;
			
			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);
			
			switch (opcode) {
				case oAuthServHostname:
					host = safe_strdup(p2);
					break;
				case oAuthServPath:
					free(path);
					path = safe_strdup(p2);
					break;
				case oAuthServSSLPort:
					ssl_port = atoi(p2);
					break;
				case oAuthServHTTPPort:
					http_port = atoi(p2);
					break;
				case oAuthServSSLAvailable:
					ssl_available = parse_boolean_value(p2);
					if (ssl_available < 0)
						ssl_available = 0;
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}

		/* Read next line */
		memset(line, 0, MAX_BUF);
		fgets(line, MAX_BUF - 1, file);
		(*linenum)++; /* increment line counter. */
	}

	/* only proceed if we have an host and a path */
	if (host == NULL)
		return;
	
	debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list",
			host, http_port, ssl_port, path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_auth_serv));
	
	/* Fill in struct */
	memset(new, 0, sizeof(t_auth_serv)); /*< Fill all with NULL */
	new->authserv_hostname = host;
	new->authserv_use_ssl = ssl_available;
	new->authserv_path = path;
	new->authserv_http_port = http_port;
	new->authserv_ssl_port = ssl_port;
	
	/* If it's the first, add to config, else append to last server */
	if (config.auth_servers == NULL) {
		config.auth_servers = new;
	} else {
		for (tmp = config.auth_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}
	
	debug(LOG_DEBUG, "Auth server added");
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(char *ruleset, FILE *file, char *filename, int *linenum)
{
	char		line[MAX_BUF],
			*p1,
			*p2;
	int		opcode;

	debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);
	
	/* Read first line */	
	memset(line, 0, MAX_BUF);
	fgets(line, MAX_BUF - 1, file);
	(*linenum)++; /* increment line counter. */

	/* Parsing loop */
	while ((line[0] != '\0') && (strchr(line, '}') == NULL)) {
		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;
			
			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);
			
			switch (opcode) {
				case oFirewallRule:
					_parse_firewall_rule(ruleset, p2);
					break;

				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}

		/* Read next line */
		memset(line, 0, MAX_BUF);
		fgets(line, MAX_BUF - 1, file);
		(*linenum)++; /* increment line counter. */
	}

	debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(char *ruleset, char *leftover)
{
	int i;
	int block_allow = 0; /**< 0 == block, 1 == allow */
	int direction = 0; /**< 0 == to, 1 == from */ 
	int all_nums = 1; /**< If 0, port contained non-numerics */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port to open/block */
	char *protocol = NULL; /**< protocol to block, tcp/udp/icmp */
	char *mask = NULL; /**< Netmask */
	char *other_kw = NULL; /**< other key word */
	t_firewall_ruleset *tmpr;
	t_firewall_ruleset *tmpr2;
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	debug(LOG_DEBUG, "leftover: %s", leftover);

	/* lower case */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower(*(leftover + i))); i++);
	
	token = leftover;
	TO_NEXT_WORD(leftover, finished);
	
	/* Parse token */
	if (!strcasecmp(token, "block") || finished) {
		block_allow = 0;
	} else if (!strcasecmp(token, "allow")) {
		block_allow = 1;
	} else {
		debug(LOG_ERR, "Invalid rule type %s, expecting "
				"\"block\" or \"allow\"", token);
		return -1;
	}

	/* Parse the remainder */
	/* Get the protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* should be exactly "port" */
	if (strncmp(leftover, "port", 4) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit(*(port + i)))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid port %s", port);
			return -3; /*< Fail */
		}
	}

	/* Now, further stuff is optional */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strncmp(other_kw, "to", 2)==0) {
			debug(LOG_DEBUG, "direction is 'to'");
			goto direction_done;
		} 
		if (strncmp(other_kw, "from", 4)==0) {
			debug(LOG_DEBUG, "direction is 'from'");
			direction = 1;
			goto direction_done;
		}
		if (finished) {
			debug(LOG_ERR, "Invalid or unexpected keyword '%s', "
					"expecting \"to\" or \"from\"", other_kw);
			return -4; /*< Fail */
		}
		direction_done:
		
		/* Get port now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit(*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid mask %s", mask);
			return -3; /*< Fail */
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->block_allow = block_allow;
	tmp->direction   = direction;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);
	
	/* Append the rule record */
	if (config.rulesets == NULL) {
		config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
		memset(config.rulesets, 0, sizeof(t_firewall_ruleset));
		config.rulesets->name = safe_strdup(ruleset);
		tmpr = config.rulesets;
	} else {
		tmpr2 = tmpr = config.rulesets;
		while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
			tmpr2 = tmpr;
			tmpr = tmpr->next;
		}
		if (tmpr == NULL) {
			/* Rule did not exist */
			tmpr = safe_malloc(sizeof(t_firewall_ruleset));
			memset(tmpr, 0, sizeof(t_firewall_ruleset));
			tmpr->name = safe_strdup(ruleset);
			tmpr2->next = tmpr;
		}
	}

	/* At this point, tmpr == current ruleset */
	if (tmpr->rules == NULL) {
		/* No rules... */
		tmpr->rules = tmp;
	} else {
		tmp2 = tmpr->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}
	
	return 1;
}

t_firewall_rule *
get_ruleset(char *ruleset)
{
	t_firewall_ruleset	*tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	if (tmp == NULL)
		return NULL;

	return(tmp->rules);
}

/**
@param filename Full path of the configuration file to be read 
*/
void
config_read(char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2, *p3, *p4;
	int linenum = 0, opcode, value, len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, ' '))) {
			p1[0] = '\0';
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';
		}

		if (p1) {
			p1++;

			// Trim leading spaces
			len = strlen(p1);
			while (*p1 && len) {
				if (*p1 == ' ')
					p1++;
				else
					break;
				len = strlen(p1);
			}


			p2 = strchr(p1, ' ');
			/*
			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else
			*/
			if ((p3 = strstr(p1, "\r\n"))) {
				p3[0] = '\0';
			} else if ((p4 = strchr(p1, '\n'))) {
				p4[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = config_parse_token(s, filename, linenum);

				if (p2&&(p2[0]==' ')&&(!((opcode==oNodeName)||(opcode==oNetwork)))) p2[0]='\0';

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oExternalInterface:
					config.external_interface = safe_strdup(p1);
					break;
				case oGatewayID:
					config.gw_id = safe_strdup(p1);
					break;
				case oGatewayInterface:
					parse_gateway_interface(p1);
					break;
				case oGatewayAddress:
					config.gw_address = safe_strdup(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthServer:
					parse_auth_server(fd, filename,
							&linenum);
					break;
				case oFirewallRuleSet:
					parse_firewall_ruleset(p1, fd, filename, &linenum);
					break;
				case oTrustedMACList:
					parse_trusted_mac_list(p1);
					break;
				case oOwnerMACList:
					parse_owner_mac_list(p1);
					break;
				case oHTTPDName:
					config.httpdname = safe_strdup(p1);
					break;
				case oOwner:
					config.Owner = safe_strdup(p1);
					break;
				case oNetwork:
					config.Network = safe_strdup(p1);
					break;
				case oLat:
					config.Lat = safe_strdup(p1);
					break;
				case oLon:
					config.Lon = safe_strdup(p1);
					break;
				case oDebugLevel:
					sscanf(p1, "%d", &config.debuglevel);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oBadOption:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oWdctlSocket:
					free(config.wdctl_sock);
					config.wdctl_sock = safe_strdup(p1);
					break;
				case oClientTimeout:
					sscanf(p1, "%d", &config.clienttimeout);
					break;
				case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				case oProxyPort:
					sscanf(p1, "%d", &config.proxy_port);
					break;
				case oNodeName:
					config.NodeName = safe_strdup(p1);
					break;
				case oSmtpServer:
					config.SmtpServer = safe_strdup(p1);
					break;
				case oIptables:
					config.Iptables = safe_strdup(p1);
					break;
				}
			}
		}
	}

	fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}

void parse_trusted_mac_list(char *ptr) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	t_trusted_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

			if (config.trustedmaclist == NULL) {
				config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
				config.trustedmaclist->mac = safe_strdup(mac);
				config.trustedmaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.trustedmaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_trusted_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}

void parse_owner_mac_list(char *ptr) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	t_owner_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for owner MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to owner trusted list", mac);

			if (config.ownermaclist == NULL) {
				config.ownermaclist = safe_malloc(sizeof(t_owner_mac));
				config.ownermaclist->mac = safe_strdup(mac);
				config.ownermaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.ownermaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_owner_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}
void parse_gateway_interface(char *ptr) {
	char *ptrcopy = NULL;
	char *possibleinterface = NULL;
	char *interface = NULL;
	t_gateway_interface *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for interfaces", ptr);

	interface = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possibleinterface = strsep(&ptrcopy, ", "))) {
		if (sscanf(possibleinterface, "%s", interface) == 1) {
			/* Copy interface to the list */

			debug(LOG_DEBUG, "Adding interface [%s] to gateway interface list", interface);

			if (config.gw_interface == NULL) {
				config.gw_interface = safe_malloc(sizeof(t_gateway_interface));
				config.gw_interface->interface = safe_strdup(interface);
				config.gw_interface->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.gw_interface; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_gateway_interface));
				p = p->next;
				p->interface = safe_strdup(interface);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(interface);

}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");
    config_notnull(config.auth_servers, "AuthServer");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(void *parm, char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{

	/* This is as good as atomic */
	return config.auth_servers;
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv *bad_server)
{
	t_auth_serv	*tmp;

	if (config.auth_servers == bad_server && bad_server->next != NULL) {
		/* Go to the last */
		for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next);
		/* Set bad server as last */
		tmp->next = bad_server;
		/* Remove bad server from start of list */
		config.auth_servers = bad_server->next;
		/* Set the next pointe to NULL in the last element */
		bad_server->next = NULL;
	}

}
