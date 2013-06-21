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

/* $Id: http.c 1239 2007-05-30 19:21:21Z david $ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author 2006 Pascal Rullier <pascal.rullier@wireless-fr.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"

#include "util.h"

#include "../config.h"

extern pthread_mutex_t	client_list_mutex;

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd *webserver, request *r)
{
	char		*newlocation,
			*protocol,
			tmp_url[MAX_BUF],
			*url;
	int		port;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}

	memset(tmp_url, 0, sizeof(tmp_url));
	/* 
	 * XXX Note the code belows assume that the client's request is a plain
	 * http request to a standard port. At any rate, this handler is called only
	 * if the internet/auth server is down so it's not a huge loss, but still.
	 */
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
			r->request.path,
			r->request.query[0] ? "?" : "",
			r->request.query);
	url = httpdUrlEncode(tmp_url);

	if (!is_online()) {
		/* The internet connection is down at the moment  - apologize and do not redirect anywhere */
		http_wifidog_header(r, "L'acc&eacute;s internet est indisponible");
		httpdOutput(r, "<p>Nous sommes d&eacute;sol&eacute;s, mais il semble que la connexion internet est temporairement indisponible.</p>");
		httpdOutput(r, "<p>Si cela est possible, veuillez avertir les propri&eacute;taires de ce point d'acc&egrave;s.</p>");
		httpdOutput(r, "<p>Les administrateurs de ce r&eacute;seau sont au courant de cette interruption. Nous esp&eacute;rons que cette situation sera r&eacute;solue bient&ocirc;t.</p>");
		httpdPrintf(r, "<p>Dans un moment, veuillez <a href='%s'>cliquer ici</a> pour relancer votre requ&ecirc;te.</p>", tmp_url);
		http_wifidog_footer(r);
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else if (!is_auth_online()) {
		/* The auth server is down at the moment - apologize and do not redirect anywhere */
		http_wifidog_header(r, "L'&eacute;cran de connexion est indisponible");
		httpdOutput(r, "<p>Nous sommes d&eacute;sol&eacute;s, mais il semble que nous sommes actuellement incapables de vous rediriger sur la page de connexion.</p>");
		httpdOutput(r, "<p>Les administrateurs de ce r&eacute;seau sont au courant de cette interruption. Nous esp&eacute;rons que cette situation sera bient&ocirc;t r&eacute;solue.</p>");
		httpdPrintf(r, "<p>Dans un moment, veuillez <a href='%s'>cliquer ici</a> pour relancer votre requ&ecirc;te.</p>", tmp_url);
		http_wifidog_footer(r);
		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
	}
	else {
		/* Node traversal to be coded here */

		/* Re-direct them to auth server */
		safe_asprintf(&newlocation, "Location: %s://%s:%d%slogin?gw_address=%s&gw_port=%d&gw_id=%s&url=%s",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path,
			config->gw_address,
			config->gw_port, 
			config->gw_id,
			url);
		httpdSetResponse(r, "307 Please authenticate yourself here\n");
		httpdAddHeader(r, newlocation);
		http_wifidog_header(r, "Redirection");
		httpdPrintf(r, "Please <a href='%s://%s:%d%slogin?gw_address=%s&gw_port=%d&gw_id=%s&url=%s'>click here</a> to login",
				protocol,
				auth_server->authserv_hostname,
				port,
				auth_server->authserv_path,
				config->gw_address, 
				config->gw_port,
				config->gw_id,
				url);
		http_wifidog_footer(r);
		debug(LOG_INFO, "Captured %s requesting [%s] and re-directed them to login page", r->clientAddr, url);
		free(newlocation);
	}

	free(url);
}

void 
http_callback_wifidog(httpd *webserver, request *r)
{
	http_wifidog_header(r, "WiFiDog");
	httpdOutput(r, "Veuillez utiliser le menu pour visualiser les caract&eacute;ristiques de cette installation de WiFiDog.");
	http_wifidog_footer(r);
}

void 
http_callback_about(httpd *webserver, request *r)
{
	http_wifidog_header(r, "A propos de WiFiDog");
	httpdOutput(r, "WiFiDog version <b>" VERSION "</b>");
	http_wifidog_footer(r);
}

void 
http_callback_status(httpd *webserver, request *r)
{
	char * status = NULL;
	status = get_status_text(0);
	http_wifidog_header(r, "Etat WiFiDog");
	httpdOutput(r, "<pre>");
	httpdOutput(r, status);
	httpdOutput(r, "</pre>");
	http_wifidog_footer(r);
	free(status);
}

void 
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;

	if ((token = httpdGetVariableByName(r, "token"))) {
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			http_wifidog_header(r, "WiFiDog Error");
			httpdOutput(r, "Failed to retrieve your MAC address");
			http_wifidog_footer(r);
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s", r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);
			} else {
				debug(LOG_DEBUG, "Node for %s already exists", client->ip);
			}

			UNLOCK_CLIENT_LIST();

			authenticate_client(r);
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		http_wifidog_header(r, "WiFiDog Error");
		httpdOutput(r, "Invalid token");
		http_wifidog_footer(r);
	}
}

void
http_wifidog_header(request *r, char *title)
{
    httpdOutput(r, "<html>\n");
    httpdOutput(r, "<head>\n");
    httpdPrintf(r, "<title>%s</title>\n", title);
    httpdOutput(r, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>\n");

    httpdOutput(r, "<style>\n");
    httpdOutput(r, "body {\n");
    httpdOutput(r, "  margin: 10px 60px 0 60px; \n");
    httpdOutput(r, "  font-family : bitstream vera sans, sans-serif;\n");
    httpdOutput(r, "  color: #2222ff;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a {\n");
    httpdOutput(r, "  color: #00f;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:active {\n");
    httpdOutput(r, "  color: #00f;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:link {\n");
    httpdOutput(r, "  color: #00f;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:visited {\n");
    httpdOutput(r, "  color: #00f;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#header {\n");
    httpdOutput(r, "  height: 30px;\n");
    httpdOutput(r, "  background-color: #eeeeff;\n");
    httpdOutput(r, "  padding: 20px;\n");
    httpdOutput(r, "  font-size: 20pt;\n");
    httpdOutput(r, "  text-align: center;\n");
    httpdOutput(r, "  border: 2px solid #2481ff;\n");
    httpdOutput(r, "  border-bottom: 0;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#menu {\n");
    httpdOutput(r, "  width: 200px;\n");
    httpdOutput(r, "  float: right;\n");
    httpdOutput(r, "  background-color: #eeeeff;\n");
    httpdOutput(r, "  border: 2px solid #2481ff;\n");
    httpdOutput(r, "  font-size: 80%;\n");
    httpdOutput(r, "  min-height: 300px;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#menu h2 {\n");
    httpdOutput(r, "  margin: 0;\n");
    httpdOutput(r, "  background-color: #2481ff;\n");
    httpdOutput(r, "  text-align: center;\n");
    httpdOutput(r, "  color: #fff;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#copyright {\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#content {\n");
    httpdOutput(r, "  padding: 20px;\n");
    httpdOutput(r, "  border: 2px solid #2481ff;\n");
    httpdOutput(r, "  min-height: 300px;\n");
    httpdOutput(r, "}\n");
    httpdOutput(r, "</style>\n");

    httpdOutput(r, "</head>\n");

    httpdOutput(r, "<body\n");

    httpdOutput(r, "<div id=\"header\">\n");
    httpdPrintf(r, "    %s\n", title);
    httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"menu\">\n");


    httpdOutput(r, "    <h2>Info</h2>\n");
    httpdOutput(r, "    <ul>\n");
    httpdOutput(r, "    <li>Version: " VERSION "\n");
    httpdPrintf(r, "    <li>Node ID: %s\n", config_get_config()->gw_id);
    httpdPrintf(r, "    <li>Nom du Node: %s\n", config_get_config()->NodeName);
    httpdPrintf(r, "    <li>R&eacute;seau : %s\n", config_get_config()->Network);
    httpdPrintf(r, "    <li>Propri&eacute;taire : %s\n", config_get_config()->Owner);
    httpdOutput(r, "    </ul>\n");
    httpdOutput(r, "    <br>\n");

    httpdOutput(r, "    <h2>Menu</h2>\n");
    httpdOutput(r, "    <ul>\n");
    httpdOutput(r, "    <li><a href='/wifidog/status'>Etat WiFiDog</a>\n");
    httpdOutput(r, "    <li><a href='/wifidog/about'>A propos de WiFiDog</a>\n");
    httpdOutput(r, "    <li><a href='http://www.wifidog.org/'>Page d'accueil WiFiDog</a>\n");
    httpdOutput(r, "    <li><a href='http://www.wireless-fr.org/'>Page d'accueil France Wireless</a>\n");
    httpdOutput(r, "    </ul>\n");
    httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"content\">\n");
    httpdPrintf(r, "<h2>%s</h2>\n", title);
}

void
http_wifidog_footer(request *r)
{
	httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"copyright\">\n");
    httpdOutput(r, "Copyright (C) 2004-2007 Wifidog/France Wireless.  Ce logiciel est sous la license GNU GPL.\n");
    httpdOutput(r, "</div>\n");


	httpdOutput(r, "</body>\n");
	httpdOutput(r, "</html>\n");
}
