/* $Id$ */

/***
  This file is part of avahi.
 
  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.
 
  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "natmap.h"

/* XXX: Use avahi_new* allocators */

/**
 * Allocates a new map.
 * The new object will be zeroed (except for the sockets, which will be -1).
 *
 * Returns NULL on ENOMEM or the newly-created object.
 */
AvahiNatpmMap *avahi_natpm_map_create(void) {
    AvahiNatpmMap *m;
    
    m = calloc(1, sizeof(AvahiNatpmMap));

    if (!m)
        return NULL;

    m->tcp.sock = -1;
    m->udp.sock = -1;

    return m;
}

/**
 * Destroy a map.
 * Closes its sockets (if they are >= 0) and frees the memory.
 * Must not be passed NULL.
 */
void avahi_natpm_map_destroy(AvahiNatpmMap *map) {
    assert(map != NULL);

    if (map->tcp.sock >= 0)
        close(map->tcp.sock);

    if (map->udp.sock >= 0)
        close(map->udp.sock);

    free(map);
}

/**
 * The next expiry of either a TCP or UDP map.
 */
time_t avahi_natpm_map_next_expiry(const AvahiNatpmMap *map) {

    if (map->tcp.state != PORT_MAPPED) {
        assert(map->udp.state == PORT_MAPPED);
        return map->udp.expiry;
    }

    if (map->udp.state != PORT_MAPPED) {
        assert(map->tcp.state == PORT_MAPPED);
        return map->tcp.expiry;
    }

    /* Both mapped, return the smaller. */
    return (map->tcp.expiry < map->udp.expiry) ? map->tcp.expiry : map->udp.expiry;
}

/* vim: ts=4 sw=4 et tw=80
 */
