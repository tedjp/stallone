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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

#include <libdaemon/dlog.h>

#include <avahi-common/malloc.h>

#include "interface.h"

static int get_multicast_socket(const struct sockaddr_in *addr);

/**
 * Returns NULL if there is no appropriate interface.
 * Free the result with avahi_natpm_free_interface().
 */
AvahiNatpmInterface *avahi_natpm_get_public_interface_auto(void) {
    AvahiNatpmInterface *iface = NULL;
    struct ifaddrs *ifaddrs_top, *ifaddr;

    if (-1 == getifaddrs(&ifaddrs_top))
        return NULL;

    for (ifaddr = ifaddrs_top; ifaddr; ifaddr = ifaddr->ifa_next) {
        if (!ifaddr->ifa_addr)
            continue;

        if (ifaddr->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (struct sockaddr_in*)ifaddr->ifa_addr;

            if (avahi_natpm_address_visibility(sin->sin_addr.s_addr) == AVAHI_NATPM_ADDRESS_VISIBILITY_PUBLIC) {
                iface = avahi_new0(AvahiNatpmInterface, 1);
                if (!iface)
                    goto end;

                iface->index = if_nametoindex(ifaddr->ifa_name);
                iface->name = avahi_strdup(ifaddr->ifa_name);

                iface->address = sin->sin_addr.s_addr;
                break;
            }
        }
    }

end:
    freeifaddrs(ifaddrs_top);

    return iface;
}

/**
 * Determine whether an IPv4 address is on a private network or a public network.
 * All non-private networks are considered public.
 * Based on RFCs 1918 & 3330.
 */
AvahiNatpmAddressVisibility avahi_natpm_address_visibility(in_addr_t addr) {

    /* Save my brain from exploding */
    addr = ntohl(addr);

    if (   (addr & 0xff000000UL) == 0x7f000000UL) /* 127.0.0.0   /8  */
        return AVAHI_NATPM_ADDRESS_VISIBILITY_LOOPBACK;

    if (   (addr & 0xffff0000UL) == 0xc0a80000UL  /* 192.168.0.0 /16 */
        || (addr & 0xffff0000UL) == 0xa9fe0000UL  /* 169.254.0.0 /16 */
        || (addr & 0xff000000UL) == 0x0a000000UL  /* 10.0.0.0    /8  */
        || (addr & 0xfff00000UL) == 0xac100000UL) /* 172.16.0.0  /12 */
        return AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE;
    return AVAHI_NATPM_ADDRESS_VISIBILITY_PUBLIC;
}

/**
 * Frees an interface. It is safe to pass NULL.
 */
void avahi_natpm_free_interface(AvahiNatpmInterface *iface) {
    if (iface) {
        avahi_free(iface->name);
        avahi_free(iface);
    }
}

/**
 * Does _not_ close the interface's socket.
 */
void avahi_natpm_free_private_interface(AvahiNatpmPrivateInterface *iface) {
    if (iface) {
        avahi_free(iface->iface.name);
        avahi_free(iface);
    }
}

#define INIT_IFACE_ALLOC 10

/**
 * Set the provided head pointer to a linked list of private interfaces with
 * multicast sockets.
 * Returns 0 on success, -1 on error.
 * On *head will only be set on success.
 *
 * This function is too long.
 */
int avahi_natpm_get_private_interfaces(AvahiNatpmPrivateInterface **head) {
    int ret = -1;
    int snetdev = -1; /* netdevice(7) ioctl socket */
    AVAHI_LLIST_HEAD(AvahiNatpmPrivateInterface, new_head);
    int iface_alloc;
    struct ifconf ifconf;
    size_t i;

    AVAHI_LLIST_HEAD_INIT(AvahiNatpmPrivateInterface, new_head);

    snetdev = socket(PF_INET, SOCK_DGRAM, 0);
    if (snetdev == -1) {
        daemon_log(LOG_DEBUG, "%s: ipv4 control socket unavailable: %s",
                __FUNCTION__, strerror(errno));

        snetdev = socket(PF_INET6, SOCK_DGRAM, 0);

        if (snetdev == -1) {
            daemon_log(LOG_ERR, "%s: Unable to create netdev control socket: %s",
                    __FUNCTION__, strerror(errno));

            goto cleanup;
        }
    }

    iface_alloc = INIT_IFACE_ALLOC / 2;
    ifconf.ifc_req = NULL;

    assert(iface_alloc > 0);

    do {
        avahi_free(ifconf.ifc_req);

        iface_alloc *= 2;

        daemon_log(LOG_DEBUG, "%s: Allocating for %d structures",
                __FUNCTION__, iface_alloc);

        ifconf.ifc_len = iface_alloc * sizeof(struct ifreq);
        ifconf.ifc_req = avahi_new(struct ifreq, iface_alloc);

        if (ifconf.ifc_req == NULL) {
            daemon_log(LOG_ERR, "%s: Out of memory", __FUNCTION__);
            goto cleanup;
        }

        if (-1 == ioctl(snetdev, SIOCGIFCONF, &ifconf)) {
            daemon_log(LOG_ERR, "%s: ioctl(SIOCGIFCONF) failed to get interfaces: %s",
                    __FUNCTION__, strerror(errno));
            
            goto cleanup;
        }
    } while (((size_t)ifconf.ifc_len) == iface_alloc * sizeof(struct ifreq));

    for (i = 0; i * sizeof(struct ifreq) < (size_t)ifconf.ifc_len; ++i) {
        const struct sockaddr_in *sin;
        struct ifreq *ifreq = &ifconf.ifc_req[i];

        if (ifreq->ifr_addr.sa_family != AF_INET)
            continue;

        sin = (struct sockaddr_in*)(&ifreq->ifr_addr);
        if (   avahi_natpm_address_visibility(sin->sin_addr.s_addr) == AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE
            || avahi_natpm_address_visibility(sin->sin_addr.s_addr) == AVAHI_NATPM_ADDRESS_VISIBILITY_LOOPBACK) {

            struct ifreq ifreq_flags;
            AvahiNatpmPrivateInterface *newif;

            strncpy(ifreq_flags.ifr_name, ifreq->ifr_name, IFNAMSIZ);
            ifreq_flags.ifr_name[IFNAMSIZ - 1] = '\0';

            if (-1 == ioctl(snetdev, SIOCGIFFLAGS, &ifreq_flags)) {
                daemon_log(LOG_ERR, "%s: SIOCGIFFLAGS ioctl failed on %s",
                        __FUNCTION__, ifreq->ifr_name);
                continue;
            }

            if ((ifreq_flags.ifr_flags & IFF_MULTICAST) == 0) {
                daemon_log(LOG_INFO, "%s: Skipping %s (not multicast-enabled)",
                        __FUNCTION__, ifreq->ifr_name);
                continue;
            }

            /* Fill in interface structure and add it to the llist. */
            
            newif = avahi_new0(AvahiNatpmPrivateInterface, 1);

            if (!newif) {
                daemon_log(LOG_ERR, "%s: Out of memory", __FUNCTION__);
                goto cleanup;
            }

            AVAHI_LLIST_INIT(AvahiNatpmPrivateInterface, ifa, newif);

            /* XXX: I wrote this at SFO after a long day. There are probably
             * bugs. */

            /* newif.iface.index = ; */
            {
                struct ifreq iftmp;
                strncpy(iftmp.ifr_name, ifreq->ifr_name, sizeof(iftmp.ifr_name));
                iftmp.ifr_name[sizeof(iftmp.ifr_name)-1] = '\0'; /* Ensure NUL-termination */
                if (-1 == ioctl(snetdev, SIOCGIFINDEX, &iftmp)) {
                    daemon_log(LOG_ERR, "%s: ioctl(SIOCGIFINDEX) failed: %s",
                            __FUNCTION__, strerror(errno));
                    avahi_free(newif);
                    goto cleanup;
                }
                newif->iface.index = iftmp.ifr_ifindex;
            }

            /* newif.iface.name = ; */
            newif->iface.name = avahi_strdup(ifreq->ifr_name);
            if (!newif->iface.name) {
                daemon_log(LOG_ERR, "%s: Out of memory", __FUNCTION__);
                avahi_free(newif);
                goto cleanup;
            }

            /* newif.sock = ; */
            newif->sock = get_multicast_socket((struct sockaddr_in*)&ifreq->ifr_addr);
            if (newif->sock == -1) {
                avahi_free(newif);
                goto cleanup;
            }

            /* OK, everything worked */
            AVAHI_LLIST_PREPEND(AvahiNatpmPrivateInterface, ifa, new_head, newif);
        }
    }

    ret = 0;
    *head = new_head;

cleanup:
    if (snetdev >= 0)
        close(snetdev);

    avahi_free(ifconf.ifc_req);

    if (ret != 0) {
        /* Remove any items that were added */
        while(new_head)
            AVAHI_LLIST_REMOVE(AvahiNatpmPrivateInterface, ifa, new_head, new_head);
    }

    return ret;
}

int get_multicast_socket(const struct sockaddr_in *addr) {
    int sock = -1;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    if (!sock) {
        daemon_log(LOG_ERR, "%s: Unable to create socket: %s",
                __FUNCTION__, strerror(errno));
        goto fail;
    }

    if (-1 == bind(sock, (const struct sockaddr *)addr, sizeof(struct sockaddr_in))) {
        daemon_log(LOG_ERR, "%s: Unable to bind socket: %s",
                __FUNCTION__, strerror(errno));
        goto fail;
    }

    daemon_log(LOG_DEBUG, "%s: Socket created and bound OK", __FUNCTION__);

    return sock;

fail:
    if (sock != -1)
        close(sock);

    return -1;
}
/* hey vim: ts=4:sw=4:et:tw=80
 */
