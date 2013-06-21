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

/* $Id: centralserver.h 1104 2006-10-09 00:58:46Z acv $ */
/** @file centralserver.h
    @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

/** @brief Ask the central server to login a client */
#define REQUEST_TYPE_LOGIN     "login"
/** @brief Notify the the central server of a client logout */
#define REQUEST_TYPE_LOGOUT    "logout"
/** @brief Update the central server's traffic counters */
#define REQUEST_TYPE_COUNTERS  "counters"

/** @brief Initiates a transaction with the auth server */
t_authcode auth_server_request(t_authresponse *authresponse, char *request_type, char *ip, char *mac, char *token, unsigned long long int incoming, unsigned long long int outgoing);

/** @brief Tries really hard to connect to an auth server.  Returns a connected file descriptor or -1 on error */
int connect_auth_server();

/** @brief Helper function called by connect_auth_server() to do the actual work including recursion - DO NOT CALL DIRECTLY */
int _connect_auth_server(int level);

#endif /* _CENTRALSERVER_H_ */
