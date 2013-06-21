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

/* $Id: ping_thread.c 1162 2007-01-06 23:51:02Z benoitg $ */
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"

static void ping(void);

extern time_t started_time;

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_ping(void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Make sure we check the servers at the very begining */
		debug(LOG_DEBUG, "Running ping()");
		ping();
		
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
}

#define encode(c) ((c<0x20)||(c>=0x7F)||strchr("$&+,/:;=?@ \"<>#%{}|\\^~[]`",c)) 

char* url_encode (char* source) {
	unsigned char	c;
	int		i,len;
	char*		dest;
	/* calcule la taille de la chaine */
	for(i=0,len=1;source[i]!='\0';i++) 
		if encode(source[i]) len+=3;
		else len+=1;
	/* alloue le buffer */
	dest = (char*)safe_malloc(len);
	/* effectue la transformation */
	for(i=0;c=*source,c!='\0';source++) {
		if encode(c){
			sprintf(&(dest[i]),"%%%02x",c);
			i+=3;
		} else dest[i++]=c;
	}
	dest[i]='\0';
	return dest;
}

/** @internal
 * This function does the actual request.
 */
static void
ping(void)
{
	size_t			numbytes,
				totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	char*			network;
	char*			nodename;
	fd_set			readfds;
	struct timeval		timeout;
	s_config*		conf;
	FILE * fh;
	unsigned long int sys_uptime  = 0;
	unsigned int      sys_memfree = 0;
	float             sys_load    = 0;


	debug(LOG_DEBUG, "Entering ping()");
	
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		return;
	}

	/*
	 * Populate uptime, memfree and load
	 */
	if ((fh = fopen("/proc/uptime", "r"))) {
		fscanf(fh, "%lu", &sys_uptime);
		fclose(fh);
	}
	if ((fh = fopen("/proc/meminfo", "r"))) {
		while (!feof(fh)) {
			if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
				/* Not on this line */
				while (!feof(fh) && fgetc(fh) != '\n');
			}
			else {
				/* Found it */
				break;
			}
		}
		fclose(fh);
	}
	if ((fh = fopen("/proc/loadavg", "r"))) {
		fscanf(fh, "%f", &sys_load);
		fclose(fh);
	}

	/*
	 * Prep & send request
	 */
	conf = config_get_config();
	network = url_encode(conf->Network);
	nodename = url_encode(conf->NodeName);
	snprintf(request, sizeof(request) - 1,
			"GET %sping/?gw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&wifidog_uptime=%lu&prop=%s&network_id=%s&lat=%s&lon=%s&node_name=%s HTTP/1.0\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			conf->auth_servers->authserv_path,
			conf->gw_id,
			sys_uptime,
			sys_memfree,
			sys_load,
			(long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
			conf->Owner,
			network,
			conf->Lat,
			conf->Lon,
			nodename,
			VERSION,
			conf->auth_servers->authserv_hostname);

	free(network);
	free(nodename);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);
	
	send(sockfd, request, strlen(request), 0);

	debug(LOG_DEBUG, "Reading response");
	
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);
	
	if (strstr(request, "Pong") == 0) {
		debug(LOG_WARNING, "Auth server did NOT say pong!");
		/* FIXME */
	}
	else {
		debug(LOG_DEBUG, "Auth Server Says: Pong");
	}

	return;	
}
