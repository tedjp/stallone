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

/*
 * Test program (client) for NAT-PMP.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#include <avahi-common/malloc.h>
#include <avahi-common/fdutil.h>
#include <avahi-common/gccmacro.h>

#include "../common.h"
#include "../packetdump.h"
#include "gateway.h"

#define DEFAULT_MAP_LIFETIME 30
#define RESPONSE_WAIT_TIME_MSEC 5000

enum {
    ARG_OP,
    ARG_PRIVPORT,
    ARG_PUBPORT,
    ARG_PROTO,
    ARG_TIME,
    ARG_EXPECT_ARGC_MAP /**< argc expected for [un]map ops */
};

static struct in_addr gateway_addr;

static void prepare_outgoing_packet(AvahiNPPacket *pkt) {

    assert(pkt);

    memset(pkt, '\0', sizeof(*pkt));

    pkt->addr.sin_family = AF_INET;
    pkt->addr.sin_port = htons(NATPMP_PORT);
    pkt->addr.sin_addr = gateway_addr;
    pkt->data.common.version = 0;

    pkt->sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (pkt->sock == -1) {
        perror("socket");
        exit(1);
    }

    avahi_set_nonblock(pkt->sock);
}

static void send_packet(const AvahiNPPacket *pkt) {
    ssize_t size;

    assert(pkt);

    size = sendto(pkt->sock, &pkt->data, pkt->datalen, 0,
            (struct sockaddr*)&pkt->addr, sizeof(pkt->addr));

    if (size == -1) {
        perror("sendto");
        exit(1);
    }

    if (size != pkt->datalen) {
        fprintf(stderr, "size[%zd] != pkt->datalen[%zd], "
                "looks like somebody set up us the bomb. "
                "Continuing anyway.\n",
                size, pkt->datalen);
    }
}

static void recv_packet(AvahiNPPacket *pkt) {
    struct sockaddr_in fromaddr;
    socklen_t fromlen = sizeof(fromaddr);
    ssize_t size;

    assert(pkt);

    {
        struct pollfd pfd;
        pfd.fd = pkt->sock;
        pfd.events = POLLIN;
        int ret;

        ret = poll(&pfd, 1, RESPONSE_WAIT_TIME_MSEC);

        if (ret == -1) {
            perror("poll");
            exit(1);
        }
        if (ret == 0) {
            fprintf(stderr, "Timed out waiting %d ms for a response\n",
                    RESPONSE_WAIT_TIME_MSEC);
            exit(2);
        }
        if ((pfd.revents & POLLHUP) && !(pfd.revents & POLLIN)) {
            fprintf(stderr, "Socket closed without a response\n");
            exit(2);
        }
    }

    size = recvfrom(pkt->sock, &pkt->data, sizeof(pkt->data), 0,
            (struct sockaddr *)&fromaddr, &fromlen);

    if (size == -1) {
        perror("recvfrom");
        exit(1);
    }

    if (memcmp(&fromaddr, &pkt->addr, sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Received response from unexpected source %s:%hu\n",
                ip4_addr_str(fromaddr.sin_addr), ntohs(fromaddr.sin_port));
        exit(1);
    }

    pkt->datalen = size;
}

typedef void (*ClientAction)(int argc, char *argv[]);

static void op_get_public(int argc AVAHI_GCC_UNUSED, char *argv[] AVAHI_GCC_UNUSED) {
    AvahiNPPacket pkt;

    prepare_outgoing_packet(&pkt);

    pkt.datalen = 2;
    pkt.data.common.opcode = NATPMP_OPCODE_PUBLIC_ADDR;

    send_packet(&pkt);

    recv_packet(&pkt);

    fprintf(stdout, "Received the following packet: %s\n",
            avahi_natpmp_pkt_dump(&pkt));
}

static void op_map(int argc, char *argv[]) {
    AvahiNPPacket pkt;

    if (argc < ARG_EXPECT_ARGC_MAP) {
        fprintf(stderr, "Not enough args for map. "
                "Expected <priv-port> <pub-port> <proto> <time>\n");
        exit(1);
    }

    prepare_outgoing_packet(&pkt);
    pkt.datalen = 12;

    /* proto */
    if (strcasecmp("udp", argv[ARG_PROTO]) == 0)
        pkt.data.common.opcode = NATPMP_OPCODE_MAP_UDP;
    else if (strcasecmp("tcp", argv[ARG_PROTO]) == 0)
        pkt.data.common.opcode = NATPMP_OPCODE_MAP_TCP;
    else {
        fprintf(stderr, "Invalid protocol %s, use TCP or UDP\n", argv[ARG_PROTO]);
        exit(1);
    }

    /* ports */
    {
        long int port;
        char *ptr;

        port = strtol(argv[ARG_PRIVPORT], &ptr, 0);
        if (*ptr != '\0' || port < 0 || port > UINT16_MAX) {
            fprintf(stderr, "Invalid port %s\n", argv[ARG_PRIVPORT]);
            exit(1);
        }
        /* priv */
        pkt.data.u16[2] = htons(port);

        port = strtol(argv[ARG_PUBPORT], &ptr, 0);
        if (*ptr != '\0' || port < 0 || port > UINT16_MAX) {
            fprintf(stderr, "Invalid port %s\n", argv[ARG_PUBPORT]);
            exit(1);
        }
        /* pub */
        pkt.data.u16[3] = htons(port);
    }

    /* time */
    {
        /* We do some acrobatics to be signed/unsigned safe as well as avoiding
         * strtoul which is not portable. */
        long int signed_secs;
        unsigned long int secs;
        char *ptr;

        signed_secs = strtol(argv[ARG_TIME], &ptr, 0);
        secs = signed_secs;
        /* Allowing time of zero for an easy way to unmap */
        if (*ptr != '\0' || signed_secs < 0 || secs > UINT32_MAX) {
            fprintf(stderr, "Bad lifetime %s, using %u instead.\n",
                    argv[ARG_TIME], DEFAULT_MAP_LIFETIME);
            pkt.data.u32[2] = htonl(DEFAULT_MAP_LIFETIME);
        } else {
            pkt.data.u32[2] = htonl(secs);
        }
    }

    send_packet(&pkt);

    recv_packet(&pkt);

    fprintf(stdout, "Received this response: %s\n",
            avahi_natpmp_pkt_dump(&pkt));
}

static void op_unmap(int argc, char *argv[]) {
    /* Just replace the arg that is the time with "0" and call op_map */

    if (argc != ARG_EXPECT_ARGC_MAP) {
        fprintf(stderr, "Expected %d arguments but got %d. "
                "See the help for the map command.\n",
                ARG_EXPECT_ARGC_MAP, argc);
        exit(1);
    }

    /* Time=0 means unmap. Magic! */
    argv[ARG_TIME] = "0";
    op_map(argc, argv);
}

void help_and_exit(const char *argv0, int exitcode) {
    FILE *stream = exitcode ? stderr : stdout;

    fprintf(stream,
            "Usage: %s [-g <gateway-addr>] <command> [<args>...]\n"
            "  Commands:\n"
            "    get-public\n"
            "    map        <priv-port> <pub-port> <proto> <time>\n"
            "    unmap      <priv-port> <pub-port> <proto> 0\n"
            ,argv0);

    exit(exitcode);
}

static struct {
    const char *const cmdname;
    ClientAction action;
} clientcmds[] = {
    {"get-public", op_get_public},
    {"map", op_map},
    {"unmap", op_unmap},
};

int main(int argc, char *argv[]) {
    ClientAction action = NULL;
    size_t i;
    const char *argv0 = argv[0];

    if (    argc == 1
        || (argc == 2 && strcmp(argv[1],"-h") == 0)
        || (argc == 2 && strcmp(argv[1],"--help") == 0)) {
        help_and_exit(argv[0], argc == 2 ? 0 : 1);
    }

    if (argc >= 3 && strcmp(argv[1], "-g") == 0) {
        int ret;

        ret = inet_pton(AF_INET, argv[2], &gateway_addr);
        if (ret < 0) {
            fprintf(stderr, "inet_pton didn't understand AF_INET\n");
            exit(1);
        }
        if (ret == 0) {
            fprintf(stderr, "Could not parse \"%s\" as an IPv4 address\n",
                    argv[2]);
            exit(1);
        }

        argc -= 2;
        argv = &argv[2];
    } else {
        if (avahi_natpm_get_gateway(&gateway_addr)) {
            fprintf(stderr, "Failed to get gateway address\n");
            exit(2);
        }
    }

    if (argc < 2)
        help_and_exit(argv[0], 1);

    for (i = 0; i < sizeof(clientcmds) / sizeof(clientcmds[0]); ++i) {
        if (strcmp(clientcmds[i].cmdname, argv[1]) == 0) {
            action = clientcmds[i].action;
            break;
        }
    }

    if (!action)
        help_and_exit(argv0, 1);

    --argc;
    argv++;

    fprintf(stdout, "Sending request to %s...\n", ip4_addr_str(gateway_addr));

    action(argc, argv);

    fprintf(stdout, "(And everything went fine!)\n");

    return 0;
}

/* vim: ts=4 sw=4 et tw=80
 */
