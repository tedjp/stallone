#ifndef foonatmaphfoo
#define foonatmaphfoo

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

#include <stdint.h>

#include <avahi-common/address.h>
#include <avahi-common/cdecl.h>
#include <avahi-common/gccmacro.h>
#include <avahi-common/llist.h>

#include "common.h"

AVAHI_C_DECL_BEGIN

typedef struct AvahiNatpmMap AvahiNatpmMap;
struct AvahiNatpmMap {
    AVAHI_LLIST_FIELDS(AvahiNatpmMap, map); /* Internal use only */
    in_addr_t private_addr;
    uint16_t public_port;
    struct per_proto {
        time_t expiry;
        enum { PORT_RESERVED = 0, PORT_UNMAPPED = 0, PORT_MAPPED = 1 } state;
        int sock; /**< Prevents local processes binding an inaccessible port */
        uint16_t private_port;
    } tcp, udp;
};

AvahiNatpmMap *avahi_natpm_map_create(void) AVAHI_GCC_MALLOC;
void avahi_natpm_map_destroy(AvahiNatpmMap *map);
time_t avahi_natpm_map_next_expiry(const AvahiNatpmMap *map) AVAHI_GCC_PURE;

AVAHI_C_DECL_END

#endif
/* vim: ts=4 sw=4 et tw=80
 */
