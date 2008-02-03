#ifndef foonatpmipch
#define foonatpmipch

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

#include <net/if.h>

#include "common.h"
#include "natmap.h"

int ipc_req_add(const AvahiNatpmMap *map, AvahiNPProto proto);
int ipc_req_remove(const AvahiNatpmMap *map, AvahiNPProto proto);
int ipc_req_prepare(const char *interface, uint16_t min_port, uint16_t max_port);
int ipc_req_cleanup(const char *interface, uint16_t min_port, uint16_t max_port);
int ipc_req_clear(void);

#endif
/* vim:ts=4:sw=4:et:tw=80
 */
