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

/* $Id: fw_iptables.c 1241 2007-06-24 04:13:13Z benoitg $ */
/** @internal
    @file fw_iptables.c
    @brief Firewall iptables functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(char *format, ...);
static char *iptables_compile(char *, char *, t_firewall_rule *);
static void iptables_load_ruleset(char *, char *, char *);

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;

/**
   Used to supress the error output of the firewall during destruction */ 
static int fw_quiet = 0;

/** @internal
 * */
static int
iptables_do_command(char *format, ...)
{
  va_list vlist;
  char *fmt_cmd,
    *cmd;
  int rc;
  s_config *config;

  config = config_get_config();

  va_start(vlist, format);
  safe_vasprintf(&fmt_cmd, format, vlist);
  va_end(vlist);

  safe_asprintf(&cmd, "%s %s", config->Iptables, fmt_cmd);

  free(fmt_cmd);

  debug(LOG_DEBUG, "Executing command: %s", cmd);
	
  rc = execute(cmd, fw_quiet);

  free(cmd);

  return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(char * table, char *chain, t_firewall_rule *rule)
{
  char	command[MAX_BUF],
    *mode;
    
  memset(command, 0, MAX_BUF);
    
  if (rule->block_allow == 1) {
    mode = safe_strdup("ACCEPT");
  } else {
    mode = safe_strdup("REJECT");
  }
    
  snprintf(command, sizeof(command),  "-t %s -A %s ",table, chain);
  if (rule->mask != NULL) {
    snprintf((command + strlen(command)), (sizeof(command) - 
					   strlen(command)), 
					   "-%c %s ", 
					   rule->direction?'s':'d',  // 0 -> destination, 1->source
					   rule->mask);
  }
  if (rule->protocol != NULL) {
    snprintf((command + strlen(command)), (sizeof(command) -
					   strlen(command)), "-p %s ", rule->protocol);
  }
  if (rule->port != NULL) {
    snprintf((command + strlen(command)), (sizeof(command) -
					   strlen(command)), "--dport %s ", rule->port);
  }
  snprintf((command + strlen(command)), (sizeof(command) - 
					 strlen(command)), "-j %s", mode);
    
  free(mode);

  /* XXX The buffer command, an automatic variable, will get cleaned
   * off of the stack when we return, so we strdup() it. */
  return(safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static void
iptables_load_ruleset(char * table, char *ruleset, char *chain)
{
  t_firewall_rule		*rule;
  char			*cmd;

  debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);
	
  for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
    cmd = iptables_compile(table, chain, rule);
    debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
    iptables_do_command(cmd);
    free(cmd);
  }

  debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

void
iptables_fw_clear_authservers(void)
{
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
  s_config *config;
  t_auth_serv *auth_server;
   
  config = config_get_config();
    
  for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
    if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
      iptables_do_command("-t filter -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
      iptables_do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
    }
  }

}

/** Initialize the firewall rules
 */
int
iptables_fw_init(void)
{
  s_config *config;
  char * gw_interface = NULL;
  char * gw_address = NULL;
  char * ext_interface = NULL;
  int gw_port = 0;
  t_trusted_mac *p;
  t_owner_mac *q;
  t_gateway_interface *gwi;
  int proxy_port;
  char * smtpserver;
  
  fw_quiet = 0;

  LOCK_CONFIG();
  config = config_get_config();
  // gw_interface = safe_strdup(config->gw_interface);
  gw_address = safe_strdup(config->gw_address);
  gw_port = config->gw_port;
  proxy_port = config->proxy_port;
  if (config->SmtpServer) smtpserver = safe_strdup(config->SmtpServer);
  else smtpserver=NULL;

  if (config->external_interface) {
    ext_interface = safe_strdup(config->external_interface);
  } else {
    ext_interface = get_ext_iface();
  }
  UNLOCK_CONFIG();
    
  /*
   *
   * Everything in the MANGLE table
   *
   */

  /* Create new chains */
  iptables_do_command("-t mangle -N " TABLE_WIFIDOG_TRUSTED);
  iptables_do_command("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t mangle -N " TABLE_WIFIDOG_INCOMING);

  /* Assign links and rules to these new chains */
  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t mangle -A PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, gwi->interface);

  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t mangle -A PREROUTING -i %s -j " TABLE_WIFIDOG_TRUSTED, gwi->interface);//this rule will be inserted before the prior one

  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t mangle -A POSTROUTING -o %s -j " TABLE_WIFIDOG_INCOMING, gwi->interface);


  for (p = config->trustedmaclist; p != NULL; p = p->next)
    iptables_do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->mac, FW_MARK_KNOWN);


  /*
   *
   * Everything in the NAT table
   *
   */

  /* Create new chains */
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_ROUTER);
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
  iptables_do_command("-t nat -N " TABLE_WIFIDOG_AUTHSERVERS);

  /* Assign links and rules to these new chains */
  debug(LOG_DEBUG,"Adding nat PREROUTING");
  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    {
      iptables_do_command("-t nat -A PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, gwi->interface);
      if(smtpserver != NULL)
	iptables_do_command(" -t nat -A PREROUTING -p tcp --dport 25 -j " TABLE_WIFIDOG_OUTGOING " --to-destination %s:25 -i %s", smtpserver, gwi->interface);
    } 

  debug(LOG_DEBUG,"Adding nat outgoing wifi_to_router");
  iptables_do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -d %s -j " TABLE_WIFIDOG_WIFI_TO_ROUTER, gw_address);

  debug(LOG_DEBUG,"Adding nat wifi_to_router for interfaces");
  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_ROUTER " -j ACCEPT -i %s", gwi->interface);

  debug(LOG_DEBUG,"Adding nat outgoing wifi_to_internet for interfaces");
  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -j " TABLE_WIFIDOG_WIFI_TO_INTERNET " -i %s", gwi->interface);


  if(proxy_port != 0){
    debug(LOG_DEBUG,"Proxy port set, setting proxy rule");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN, proxy_port);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_MEMBER, proxy_port);
  } else {
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_MEMBER);
  }

  iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
  iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);

  iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_GLOBAL);

  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d -i %s", gw_port, gwi->interface);


  /*
   *
   * Everything in the FILTER table
   *
   */

  /* Create new chains */
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_LOCKED);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_VALIDATE);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_KNOWN);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_MEMBERS);
  iptables_do_command("-t filter -N " TABLE_WIFIDOG_UNKNOWN);

  /* Assign links and rules to these new chains */

  /* Insert at the beginning */
  for (gwi = config->gw_interface ; gwi != NULL ; gwi = gwi->next)
    iptables_do_command("-t filter -I FORWARD -i %s -j " TABLE_WIFIDOG_WIFI_TO_INTERNET, gwi->interface);


  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state INVALID -j DROP");

  /* XXX: Why this? it means that connections setup after authentication 
     stay open even after the connection is done...
     iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT");*/

  //Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
  //iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);
             
  /* TCPMSS rule for PPPoE */
  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_fw_set_authservers();

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_LOCKED, FW_MARK_LOCKED);
  iptables_load_ruleset("filter", "locked-users", TABLE_WIFIDOG_LOCKED);

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_GLOBAL);
  iptables_load_ruleset("filter", "global", TABLE_WIFIDOG_GLOBAL);
  iptables_load_ruleset("nat", "global", TABLE_WIFIDOG_GLOBAL);

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_VALIDATE, FW_MARK_PROBATION);
  iptables_load_ruleset("filter", "validating-users", TABLE_WIFIDOG_VALIDATE);

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_KNOWN, FW_MARK_KNOWN);
  iptables_load_ruleset("filter", "known-users", TABLE_WIFIDOG_KNOWN);
    
  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_MEMBERS, FW_MARK_MEMBER);
  iptables_load_ruleset("filter", "member-users", TABLE_WIFIDOG_MEMBERS);

  iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);
  iptables_load_ruleset("filter", "unknown-users", TABLE_WIFIDOG_UNKNOWN);
  iptables_do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

  /* Add Owner MAC List */

  for (q = config->ownermaclist; q != NULL; q = q->next)
    {
      iptables_do_command("-t filter -A " TABLE_WIFIDOG_GLOBAL " -m mac --mac-source %s -j ACCEPT", q->mac);
      iptables_do_command("-t nat -A " TABLE_WIFIDOG_GLOBAL " -m mac --mac-source %s -j ACCEPT", q->mac);
    }

  free(gwi);
  free(gw_address);

  return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
  fw_quiet = 1;

  debug(LOG_DEBUG, "Destroying our iptables entries");

  /*
   *
   * Everything in the MANGLE table
   *
   */
  debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
  iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_TRUSTED);
  iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
  iptables_fw_destroy_mention("mangle", "POSTROUTING", TABLE_WIFIDOG_INCOMING);
  iptables_do_command("-t mangle -F " TABLE_WIFIDOG_TRUSTED);
  iptables_do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);
  iptables_do_command("-t mangle -X " TABLE_WIFIDOG_TRUSTED);
  iptables_do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

  /*
   *
   * Everything in the NAT table
   *
   */
  debug(LOG_DEBUG, "Destroying chains in the NAT table");
  iptables_fw_destroy_mention("nat", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_ROUTER);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_OUTGOING);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_ROUTER);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);

  /*
   *
   * Everything in the FILTER table
   *
   */
  debug(LOG_DEBUG, "Destroying chains in the FILTER table");
  iptables_fw_destroy_mention("filter", "FORWARD", TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_LOCKED);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_VALIDATE);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_KNOWN);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_MEMBERS);
  iptables_do_command("-t filter -F " TABLE_WIFIDOG_UNKNOWN);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_AUTHSERVERS);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_LOCKED);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_GLOBAL);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_VALIDATE);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_KNOWN);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_MEMBERS);
  iptables_do_command("-t filter -X " TABLE_WIFIDOG_UNKNOWN);

  return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(
			    char * table,
			    char * chain,
			    char * mention
			    ) {
  FILE *p = NULL;
  char *command = NULL;
  char *command2 = NULL;
  char line[MAX_BUF];
  char rulenum[10];
  int deleted = 0;

  debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", mention, table, chain);

  safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);

  if ((p = popen(command, "r"))) {
    /* Skip first 2 lines */
    while (!feof(p) && fgetc(p) != '\n');
    while (!feof(p) && fgetc(p) != '\n');
    /* Loop over entries */
    while (fgets(line, sizeof(line), p)) {
      /* Look for mention */
      if (strstr(line, mention)) {
	/* Found mention - Get the rule number into rulenum*/
	if (sscanf(line, "%9[0-9]", rulenum) == 1) {
	  /* Delete the rule: */
	  debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, mention);
	  safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
	  iptables_do_command(command2);
	  free(command2);
	  deleted = 1;
	  /* Do not keep looping - the captured rulenums will no longer be accurate */
	  break;
	}
      }
    }
    pclose(p);
  }

  free(command);

  if (deleted) {
    /* Recurse just in case there are more in the same table+chain */
    iptables_fw_destroy_mention(table, chain, mention);
  }

  return (deleted);
}

/** Set if a specific client has access through the firewall */
int
iptables_fw_access(fw_access_t type, char *ip, char *mac, int tag)
{
  int rc;

  fw_quiet = 0;

  switch(type) {
  case FW_ACCESS_ALLOW:
    iptables_do_command("-t mangle -A " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
    rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
    break;
  case FW_ACCESS_DENY:
    iptables_do_command("-t mangle -D " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
    rc = iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
    break;
  default:
    rc = -1;
    break;
  }

  return rc;
}

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
  FILE *output;
  char *script,
    ip[16],
    rc;
  unsigned long long int counter;
  t_client *p1;
  struct in_addr tempaddr;

  /* Look for outgoing traffic */
  safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_OUTGOING);
  output = popen(script, "r");
  free(script);
  if (!output) {
    debug(LOG_ERR, "popen(): %s", strerror(errno));
    return -1;
  }

  /* skip the first two lines */
  while (('\n' != fgetc(output)) && !feof(output))
    ;
  while (('\n' != fgetc(output)) && !feof(output))
    ;
  while (output && !(feof(output))) {
    rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
    if (2 == rc && EOF != rc) {
      /* Sanity*/
      if (!inet_aton(ip, &tempaddr)) {
	debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
	continue;
      }
      debug(LOG_DEBUG, "Outgoing %s Bytes=%llu", ip, counter);
      LOCK_CLIENT_LIST();
      if ((p1 = client_list_find_by_ip(ip))) {
	if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
	  p1->counters.outgoing = p1->counters.outgoing_history + counter;
	  p1->counters.last_updated = time(NULL);
	  debug(LOG_DEBUG, "%s - Updated counter.outgoing to %llu bytes", ip, counter);
	}
      } else {
	debug(LOG_ERR, "Could not find %s in client list", ip);
      }
      UNLOCK_CLIENT_LIST();
    }
  }
  pclose(output);

  /* Look for incoming traffic */
  safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_INCOMING);
  output = popen(script, "r");
  free(script);
  if (!output) {
    debug(LOG_ERR, "popen(): %s", strerror(errno));
    return -1;
  }

  /* skip the first two lines */
  while (('\n' != fgetc(output)) && !feof(output))
    ;
  while (('\n' != fgetc(output)) && !feof(output))
    ;
  while (output && !(feof(output))) {
    rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
    if (2 == rc && EOF != rc) {
      /* Sanity*/
      if (!inet_aton(ip, &tempaddr)) {
	debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
	continue;
      }
      debug(LOG_DEBUG, "Incoming %s Bytes=%llu", ip, counter);
      LOCK_CLIENT_LIST();
      if ((p1 = client_list_find_by_ip(ip))) {
	if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
	  p1->counters.incoming = p1->counters.incoming_history + counter;
	  debug(LOG_DEBUG, "%s - Updated counter.incoming to %llu bytes", ip, counter);
	}
      } else {
	debug(LOG_ERR, "Could not find %s in client list", ip);
      }
      UNLOCK_CLIENT_LIST();
    }
  }
  pclose(output);

  return 1;
}
