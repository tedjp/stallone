#ifndef foonatpmpcommonhfoo
#define foonatpmpcommonhfoo

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

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include <avahi-common/address.h>
#include <avahi-common/cdecl.h>
#include <avahi-common/gccmacro.h>
#include <avahi-common/llist.h>

AVAHI_C_DECL_BEGIN

/** #defines **/
#define NATPMP_MINPKTSIZE 2
#define NATPMP_MAXPKTSIZE 16

#define NATPMP_MCAST_ADDR   "224.0.0.1"
#define NATPMP_PORT         5351

#define NATPMP_PKT_OP_FLAG_RESPONSE 128

#define NATPMP_OPCODE_PUBLIC_ADDR   0
#define NATPMP_OPCODE_MAP_UDP       1
#define NATPMP_OPCODE_MAP_TCP       2

#define NATPMP_RESULT_SUCCESS               0
#define NATPMP_RESULT_UNSUPPORTED_VERSION   1
#define NATPMP_RESULT_REFUSED               2
#define NATPMP_RESULT_NETWORK_FAILURE       3
#define NATPMP_RESULT_NO_RESOURCES          4
#define NATPMP_RESULT_UNSUPPORTED_OPCODE    5
/* Used to ensure outgoing packets have their result codes set */
#define NATPMP_RESULT_CANARY                65535

/* This is actually valid at the protocol level, but is used internally as a
 * canary. Requests for this value will be decremented by 1. */
#define NATPMP_TIME_CANARY                  UINT_MAX

#define NATPMP_PACKET_RESENDS   10 /* Including the first */


/** types **/

typedef struct AvahiNPPacket AvahiNPPacket;
struct AvahiNPPacket {
    int sock;
    struct sockaddr_in addr;
    int ever_sent; /* true/false, only used in responses */
    ssize_t datalen;
    union {
        struct {
            uint8_t version, opcode;
            uint16_t result;
        } common;
        uint8_t  u8 [NATPMP_MAXPKTSIZE];
        uint16_t u16[NATPMP_MAXPKTSIZE / 2];
        uint32_t u32[NATPMP_MAXPKTSIZE / 4];
    } data;
};

enum AvahiNPProto {
    NATPMP_MAP_UDP = 1, /*< deprecated */
    NATPMP_PROTO_UDP = 1,
    NATPMP_MAP_TCP = 2, /*< deprecated */
    NATPMP_PROTO_TCP = 2
};
typedef enum AvahiNPProto AvahiNPProto;

const char *ip4_addr_str(struct in_addr addr) AVAHI_GCC_PURE;

AVAHI_C_DECL_END

#endif
/* vim:ts=4:sw=4:et:tw=80
 */
