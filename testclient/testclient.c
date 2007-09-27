/***
  This file is part of Stallone.
  Copright 2007  Ted Percival <ted@midg3t.net>
 
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

#include <avahi-common/malloc.h>

#include "../common.h"


/*
 * Invocation:
 * get-public
 * map <pub> <priv> [<time>]
 * unmap <pub> <priv>
 */

/* TODO: Get this from common header! */
enum natpm_op {
    OP_UNKNOWN,
    OP_GET_PUBLIC,
    OP_MAP,
    OP_UNMAP
};

enum natpm_proto {
    PROTO_UDP = 1,
    PROTO_TCP = 2
};

typedef void (*ClientAction)(int argc, char *argv[]);

static void op_get_public(int argc, char *argv[]) {
    AvahiNPPacket pkt;
    int sock;
    ssize_t ssize;
    struct sockaddr_in sockaddr_from;
    socklen_t fromlen = sizeof(sockaddr_from);

    if (argc < 3) {
        fprintf(stderr, "%s %s: Please provide the gateway address to send to.\n",
                argv[0], argv[1]);
        exit(1);
    }

    memset(&pkt, '\0', sizeof(pkt));

    pkt.addr.sin_family = AF_INET;
    pkt.addr.sin_port = htons(NATPMP_PORT);
    if (inet_pton(AF_INET, argv[2], &pkt.addr.sin_addr) <= 0) {
        fprintf(stderr, "Problem parsing gateway address\n");
        exit(1);
    }

    pkt.datalen = 2;
    pkt.data.common.version = 0;
    pkt.data.common.opcode = NATPMP_OPCODE_PUBLIC_ADDR;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    pkt.sock = sock;

    ssize = sendto(pkt.sock, &pkt.data, pkt.datalen, 0,
            (struct sockaddr*)&pkt.addr, sizeof(pkt.addr));

    if (ssize == -1) {
        perror("sendto");
        exit(1);
    }

    if (ssize != pkt.datalen) {
        fprintf(stderr, "ssize[%d] != pkt.datalen[%d], "
                "look like somebody set up us the bomb. "
                "Continuing anyway.\n",
                ssize, pkt.datalen);
    }

    /* FIXME: Make nonblocking */
    ssize = recvfrom(pkt.sock, &pkt.data, sizeof(pkt.data), 0,
            (struct sockaddr *)&sockaddr_from, &fromlen);

    if (ssize == -1) {
        perror("recvfrom");
        exit(1);
    }

    pkt.datalen = ssize;

    if (memcmp(&sockaddr_from, &pkt.addr, sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Received response from unexpected source %s:%hu\n",
                ip4_addr_str(sockaddr_from.sin_addr), ntohs(sockaddr_from.sin_port));
        exit(1);
    }

    fprintf(stdout, "Received the following packet: %s\n",
            avahi_natpmp_pkt_dump(&pkt));

    fprintf(stdout, "(And everything went fine!)\n");
}

static void op_map(int argc, char *argv[]) {
    fprintf(stderr, "map not implemented yet (sorry!)\n");
}

static void op_unmap(int argc, char *argv[]) {
    fprintf(stderr, "unmap not implemented yet (sorry!)\n");
}

struct {
    const char *const cmdname;
    ClientAction action;
} clientcmds[] = {
    {"get-public", op_get_public},
    {"map", op_map},
    {"unmap", op_unmap},
};


int main(int argc, char *argv[]) {
    enum natpm_op op = OP_UNKNOWN;
    ClientAction action = NULL;
    int i;

    if (argc == 1) {
        /* TODO: Better usage prompt */
        fprintf(stderr, "Must provide a command. Try \"%s get-public\".\n",
                argv[0]);
        return 1;
    }

    for (i = 0; i < sizeof(clientcmds) / sizeof(clientcmds[0]); ++i) {
        if (strcmp(clientcmds[i].cmdname, argv[1]) == 0) {
            action = clientcmds[i].action;
            break;
        }
    }

    if (!action) {
        fprintf(stderr, "Unknown action name \"%s\"\n", argv[1]);
        return 1;
    }

    action(argc, argv);

    return 0;

}

/* vim: ts=4 sw=4 et tw=80
 */
