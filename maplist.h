#ifndef foonatpmmaplisthfoo
#define foonatpmmaplisthfoo

/***
  This file is part of Stallone.
  Copyright 2007  Ted Percival <ted@midg3t.net>
 
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

#include <avahi-common/gccmacro.h>
#include <netinet/in.h>

#include "common.h"
#include "natmap.h"

AVAHI_C_DECL_BEGIN

int avahi_natpm_maplist_init(void);
void avahi_natpm_maplist_remove_all(void);
void avahi_natpm_maplist_cleanup(void);
const AvahiNatpmMap *avahi_natpm_maplist_peek(void) AVAHI_GCC_PURE;

int avahi_natpm_maplist_count(void) AVAHI_GCC_PURE;

int avahi_natpm_maplist_add(AvahiNatpmMap *map);
int avahi_natpm_maplist_remove(AvahiNatpmMap *map);

time_t avahi_natpm_maplist_next_expiration(void) AVAHI_GCC_PURE;
time_t avahi_natpm_maplist_update_lifetime(AvahiNatpmMap *map, AvahiNPProto proto, uint32_t lifetime);
int avahi_natpm_maplist_has_expired_items(void) AVAHI_GCC_PURE;

int avahi_natpm_maplist_find_expired(AvahiNatpmMap ***results);
int avahi_natpm_maplist_find_byhost(in_addr_t hostaddr, AvahiNatpmMap ***results);
AvahiNatpmMap *avahi_natpm_maplist_find_hostport(in_addr_t host, uint16_t priv_port);
AvahiNatpmMap *avahi_natpm_maplist_find_hostportproto(in_addr_t host, uint16_t priv_port, AvahiNPProto proto);
AvahiNatpmMap *avahi_natpm_maplist_find_by_pub_port(uint16_t pub_port);

void avahi_natpm_maplist_free_result(AvahiNatpmMap **result);

AVAHI_C_DECL_END

#endif
/* vim: ts=4 sw=4 et tw=80
 */
