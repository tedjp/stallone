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

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <avahi-common/gccmacro.h>

#include "../interface.h"

struct addrvis {
    const char *addr;
    enum AvahiNatpmAddressVisibility vis;
};

static const struct addrvis addrs[] = {
    { "127.0.0.1", AVAHI_NATPM_ADDRESS_VISIBILITY_LOOPBACK },
    { "10.0.0.1", AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE },
    { "172.16.0.1", AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE },
    { "169.254.0.1", AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE },
    { "58.0.0.1", AVAHI_NATPM_ADDRESS_VISIBILITY_PUBLIC }
};

int main(AVAHI_GCC_UNUSED int argc, AVAHI_GCC_UNUSED char *argv[]) {
    size_t i;

    for (i = 0; i < sizeof(addrs) / sizeof(addrs[0]); ++i) {
        in_addr_t ia;

        ia = inet_addr(addrs[i].addr);
        if (avahi_natpm_address_visibility(ia) != addrs[i].vis) {
            fprintf(stderr, "Unexpected visibility for %s: %d\n",
                    addrs[i].addr, avahi_natpm_address_visibility(ia));
            return 1;
        }
    }
    return 0;
}

/* vim: ts=4 sw=4 et tw=80
 */
