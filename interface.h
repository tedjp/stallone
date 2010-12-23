#ifndef fooavahinatpminterfacehfoo
#define fooavahinatpminterfacehfoo

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

#include <netinet/in.h>

#include <avahi-common/cdecl.h>
#include <avahi-common/gccmacro.h>
#include <avahi-common/llist.h>

AVAHI_C_DECL_BEGIN

enum AvahiNatpmAddressVisibility {
    AVAHI_NATPM_ADDRESS_VISIBILITY_UNKNOWN,
    AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE,
    AVAHI_NATPM_ADDRESS_VISIBILITY_PUBLIC,
    AVAHI_NATPM_ADDRESS_VISIBILITY_LOOPBACK
};

typedef enum AvahiNatpmAddressVisibility AvahiNatpmAddressVisibility;

typedef struct AvahiNatpmInterface AvahiNatpmInterface;

struct AvahiNatpmInterface {
    unsigned int index;
    char *name;
    in_addr_t address;
};

typedef struct AvahiNatpmPrivateInterface AvahiNatpmPrivateInterface;
struct AvahiNatpmPrivateInterface {
    AVAHI_LLIST_FIELDS(AvahiNatpmPrivateInterface, ifa);
    int sock;
    AvahiNatpmInterface iface;
};

AvahiNatpmInterface *avahi_natpm_get_public_interface(const char *ifacename);

int avahi_natpm_get_private_interfaces(AvahiNatpmPrivateInterface **head);

AvahiNatpmAddressVisibility avahi_natpm_address_visibility(in_addr_t addr) AVAHI_GCC_CONST;

void avahi_natpm_free_interface(AvahiNatpmInterface *iface);
void avahi_natpm_free_private_interface(AvahiNatpmPrivateInterface *iface);

AVAHI_C_DECL_END

#endif /* fooavahinatpminterfacehfoo */
/* hey vim: ts=4:sw=4:et:tw=80
 */
