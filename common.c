/***
  This file is part of Stallone.
  Copyright 2007  Ted Percival <ted@midg3t.net>
 
  Stallone is free software; you can redistribute it and/or
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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <avahi-common/malloc.h>

#include "common.h"
#include "natmap.h"


/* Returns the given address converted to a string.
 * The returned buffer is statically allocated and will be overridden by
 * subsequent calls.
 */
const char *ip4_addr_str(struct in_addr addr) {
    static char str[16];
    if (inet_ntop(AF_INET, &addr.s_addr, str, sizeof(str)))
        return str;
    else
        return "?";
}

#if 0 /* unused */
unsigned avahi_natpm_map_hash(const void *m) {
    const AvahiNatpmMap *map = m;
    unsigned hash;
    const int shift = (sizeof(hash) < 8) ? 0 : 32;

    hash  = map->private_addr.address;
    hash ^= map->private_port << (shift);
    hash ^= map->public_port << (shift + 16);
    return hash;
}

int avahi_natpm_map_equal(const void *aa, const void *bb) {
    const AvahiNatpmMap *a = aa, *b = bb;
    return a->public_port == b->public_port
        && a->private_port == b->private_port
        && a->private_addr.address == b->private_addr.address;
}
#endif /* unused */

/* vim:ts=4:sw=4:et
 */
