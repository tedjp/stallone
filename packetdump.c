/***
  This file is part of Stallone.
  Copright 2007  Ted Percival <ted@midg3t.net>
 
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

/* inet_ntop */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <avahi-common/malloc.h>

#include "packetdump.h"


/** types **/
enum {OP_REQUEST = 0, OP_RESPONSE = 128};


/** macros **/
#define OPTYPE(pkt) ((pkt)->data.common.opcode & NATPMP_PKT_OP_FLAG_RESPONSE ? OP_RESPONSE : OP_REQUEST) 
#define IS_REQUEST(pkt) (OPTYPE(pkt) == OP_REQUEST)
#define IS_RESPONSE(pkt) (OPTYPE(pkt) == OP_RESPONSE)


/** globals **/
static char *dump_str = NULL;

static const char *const result_codes[] = {
    "Success",
    "Unsupported Version",
    "Not Authorized/Refused",
    "Network Failure",
    "Out of resources",
    "Unsupported opcode"
};


/** declarations **/
static char *dump_append_public_addr(char *str, const AvahiNPPacket *pkt);
static char *dump_append_map(char *str, const AvahiNPPacket *pkt);


/** impls **/

/**
 * Frees the memory associated with a packet dump.
 * Calling this is optional - avahi_natpmp_pkt_dump() always ensures it is
 * not leaking memory.
 */
void avahi_natpmp_pkt_dump_free(void) {
    avahi_free(dump_str); /* NULL-safe */
    dump_str = NULL;
}

/**
 * Frees the specified string, ensuring it is not equal to dump_str
 * (which might lead to accidental double-free or SEGV).
 */
static void safe_free(char *oldstr) {
    if (oldstr != dump_str)
        avahi_free(oldstr);
}

/**
 * Pretty inefficient way of turning any packet into a nicely formatted, human
 * readable description.
 *
 * XXX: avahi_strdup_printf asserts on OOM (never returns NULL) so a bunch of
 * this conditional code is never going to be called.
 */
const char *avahi_natpmp_pkt_dump(const AvahiNPPacket *pkt) {
    /* Might be easier to implement this with something like avahi_astrcat().
     * At the moment this function is stupidly inefficient with all its reallocating. */
    char *oldstr;

    assert(pkt);

    avahi_natpmp_pkt_dump_free();

    /* Dump all the common parts first */
    dump_str = avahi_strdup_printf("{sock[%d] remote_addr[%s:%hu] ever_sent[%d] datalen[%d] version[%hhu] opcode[%hhu+%hhu] %s[%hu(%s)]",
            pkt->sock,
            ip4_addr_str(pkt->addr.sin_addr), ntohs(pkt->addr.sin_port), pkt->ever_sent,
            pkt->datalen, pkt->data.common.version,
            OPTYPE(pkt), pkt->data.common.opcode ^ OPTYPE(pkt),
            IS_REQUEST(pkt) ? "reserved" : "result", ntohs(pkt->data.u16[1]),
            IS_RESPONSE(pkt) && ntohs(pkt->data.common.result) < (sizeof(result_codes) / sizeof(result_codes[0])) ? result_codes[ntohs(pkt->data.common.result)] : "?");

    if (!dump_str)
        return "?";

    oldstr = dump_str;

    if (IS_RESPONSE(pkt)) {
        dump_str = avahi_strdup_printf("%s sssoe[%u]", dump_str, ntohl(pkt->data.u32[1]));
        if (!dump_str)
            return (dump_str = oldstr); /* return as much as possible */

        safe_free(oldstr);
    }

    oldstr = dump_str;

    switch(pkt->data.common.opcode & ~NATPMP_PKT_OP_FLAG_RESPONSE) {
        case NATPMP_OPCODE_PUBLIC_ADDR:
            if (IS_RESPONSE(pkt))
                dump_str = dump_append_public_addr(dump_str, pkt);
            break;

        case NATPMP_OPCODE_MAP_TCP: /* fall through */
        case NATPMP_OPCODE_MAP_UDP:
            dump_str = dump_append_map(dump_str, pkt);
            break;

        default: /* unknown opcode */
            dump_str = avahi_strdup_printf("%s (unknown opcode)", dump_str);
    }

    if (!dump_str)
        return (dump_str = oldstr); /* return as much as possible */

    safe_free(oldstr);

    /* one more time... */
    oldstr = dump_str;

    dump_str = avahi_strdup_printf("%s}", dump_str);

    if (!dump_str)
        return (dump_str = oldstr); /* return as much as possible */

    safe_free(oldstr);

    return dump_str;
}

char *dump_append_public_addr(char *str, const AvahiNPPacket *pkt) {
    char *oldstr = str;
    struct in_addr sinaddr;

    assert(str);
    assert(pkt);

    sinaddr.s_addr = pkt->data.u32[2];

    str = avahi_strdup_printf("%s pub_addr[%s]", str, ip4_addr_str(sinaddr));
    if (!str)
        return oldstr;

    return str;
}

char *dump_append_map(char *str, const AvahiNPPacket *pkt) {
    char *oldstr = str;

    assert(str);
    assert(pkt);

    str = avahi_strdup_printf("%s priv_port[%hu] pub_port[%hu] lifetime[%u]", str,
            ntohs(pkt->data.u16[IS_RESPONSE(pkt) ? 4 : 2]),
            ntohs(pkt->data.u16[IS_RESPONSE(pkt) ? 5 : 3]),
            ntohl(pkt->data.u32[IS_RESPONSE(pkt) ? 3 : 2]));

    if (!str)
        return oldstr;

    return str;
}

/* hey vim: ts=4:sw=4:et:tw=80
 */
