/***
  This file is part of Stallone.
  Copyright 2008  Ted Percival <ted@midg3t.net>
 
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
***/

/*
 * Determine the machine's default route, to which NAT-PMP packets will
 * be sent.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <libdaemon/dlog.h>

#include "gateway.h"

/* The output of /proc/net/route tends to be 384 chars per line, plus
 * \n\0 */
#define LINE_BUF_LEN 386
#define PROC_NET_ROUTE "/proc/net/route"

/** Reads a line of text up to buflen bytes long into buf from stream,
 * dropping any text that exceeds the buffer length and always reading a
 * full line.
 *
 * Returns buf if reading succeeded, or NULL on error or end of file
 * when no characters were read (like fgets).
 */
static char *get_line(char buf[], size_t buflen, FILE *stream) {
    if (!fgets(buf, buflen, stream))
        return NULL;

    if (!strchr(buf, '\n')) { /* Not at end of line yet */
        int c;
        do c = getc(stream);
        while (c != '\n' && c != EOF);
    }

    return buf;
}

/**
 * Parse the given line looking for a gateway definition.
 * If the gateway flag is set, the address is stored in *addr
 * and the function returns 1. If no gateway is found, it returns
 * 0 and the content of *addr is undefined.
 *
 * The input line will be modified during the search process.
 */
static int find_gateway(char *line, struct in_addr *addr) {
    unsigned long int flags = 0;
    char *endptr;
    const char *addrstr = NULL, *flagstr = NULL;
    unsigned int field = 1;
    union {
        struct in_addr sin_addr;
        unsigned long numeric;
    } address;

    if (!line || !addr)
        return 0;

    while ((line = strtok(field == 1 ? line : NULL, "\t "))) {
        if (field == 3)
            addrstr = line;
        else if (field == 4) {
            flagstr = line;
            break;
        }
        ++field;
    }

    if (!addrstr || !flagstr) {
        daemon_log(LOG_WARNING, "%s: Did not find %s field\n",
                __FUNCTION__, (addrstr == NULL) ? "gateway" : "flags");
        return 0;
    }

    flags = strtoul(flagstr, &endptr, 16);
    if (endptr == flagstr || *endptr != '\0') {
        daemon_log(LOG_WARNING, "%s: Could not parse flag string \"%s\"",
                __FUNCTION__, flagstr);
        return 0;
    }

    if ((flags & RTF_GATEWAY) && (flags & RTF_UP)) { /* Valid gateway */
        address.numeric = strtoul(addrstr, &endptr, 16);
        if (endptr == addrstr || *endptr != '\0') {
            daemon_log(LOG_ERR, "%s: Could not parse address string \"%s\"",
                    __FUNCTION__, addrstr);
            return 0;
        }

        *addr = address.sin_addr;

        return 1;
    }

    return 0;
}

/**
 * Gets the default route (gateway) that NAT-PMP packets should be sent
 * to.
 * Returns -1 on error, 0 on success.
 */
int avahi_natpm_get_gateway(struct in_addr *addr) {
    FILE *froute = NULL;
    char line[LINE_BUF_LEN];
    int result = -1;

    froute = fopen(PROC_NET_ROUTE, "r");
    if (!froute) {
        daemon_log(LOG_ERR, "%s: Failed to open %s: %s",
                __FUNCTION__, PROC_NET_ROUTE, strerror(errno));
        goto finish;
    }

    /* Throw away the first line -- it's a header line. */
    if (!get_line(line, sizeof(line), froute)) {
        daemon_log(LOG_ERR, "%s: Unexpected error reading %s: %s",
                __FUNCTION__, PROC_NET_ROUTE, strerror(errno));
        goto finish;
    }

    /* Look for the gateway line */
    while (get_line(line, sizeof(line), froute)) {
        if (find_gateway(line, addr)) {
            result = 0;
            break;
        }
    }

finish:
    if (froute)
        fclose(froute);

    return result;
}

/* vim: ts=4 sw=4 et tw=72
 */
