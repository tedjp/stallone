#ifndef fooworkerhfoo
#define fooworkerhfoo

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

#include <sys/types.h>

typedef struct AvahiNatpmdIPCReq AvahiNatpmdIPCReq;
struct AvahiNatpmdIPCReq {
    int result;
    enum {
        IPCREQ_OP_ADD,
        IPCREQ_OP_REMOVE,
        IPCREQ_OP_PREPARE,
        IPCREQ_OP_CLEANUP,
        IPCREQ_OP_CLEAR
    } op;
    char interface[IF_NAMESIZE]; /* Alternatively try IFNAMSIZ and file a bug report */
    in_addr_t dest_addr;
    enum { IPCREQ_PROTO_UDP = NATPMP_OPCODE_MAP_UDP, IPCREQ_PROTO_TCP = NATPMP_OPCODE_MAP_TCP } proto;
    uint16_t pub_port, dest_port;
    uint16_t min_port, max_port;
};

int worker(const char *mapping_script_file, int sock);

#endif
/* vim:ts=4:sw=4:et:tw=80
 */
