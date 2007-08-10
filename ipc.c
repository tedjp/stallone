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

#include <errno.h>
#include <string.h>

#include <libdaemon/dlog.h>

#include "ipc.h"
#include "worker.h"

extern int ipc_sock;

static int ipc_do(const AvahiNatpmdIPCReq *req);

/**
 * Prepares iptables.
 * @param   interface   The public interface that will have ports forwarded
 * @param   min_port    Lowest port for natpmd to control
 * @param   max_port    Highest port for natpmd to control
 *
 * Returns 0 on success, -1 on failure.
 */
int ipc_req_prepare(const char *interface, uint16_t min_port, uint16_t max_port) {
    AvahiNatpmdIPCReq req;

    assert(interface != NULL);
    
    if (interface[0] == '\0')
        return -1;

    memset(&req, '\0', sizeof(req));

    req.op = IPCREQ_OP_PREPARE;
    strncpy(req.interface, interface, sizeof(req.interface));
    req.interface[sizeof(req.interface)-1] = '\0';
    req.min_port = min_port;
    req.max_port = max_port;

    return ipc_do(&req);
}

/**
 * Only the protocol specified as @param proto will be mapped.
 */
int ipc_req_add(const AvahiNatpmMap *map, AvahiNPProto proto) {
    AvahiNatpmdIPCReq req;

    assert(map != NULL);

    req.op = IPCREQ_OP_ADD;
    req.dest_addr = map->private_addr;
    req.proto = (proto == NATPMP_MAP_TCP) ? IPCREQ_PROTO_TCP : IPCREQ_PROTO_UDP;
    req.pub_port = map->public_port;
    req.dest_port = (proto == NATPMP_MAP_TCP) ? map->tcp.private_port : map->udp.private_port;

    return ipc_do(&req);
}

int ipc_req_remove(const AvahiNatpmMap *map, AvahiNPProto proto) {
    AvahiNatpmdIPCReq req;

    assert(map != NULL);

    req.op = IPCREQ_OP_REMOVE;
    req.dest_addr = map->private_addr;
    req.proto = (proto == NATPMP_MAP_TCP) ? IPCREQ_PROTO_TCP : IPCREQ_PROTO_UDP;
    req.pub_port = map->public_port;
    req.dest_port = (proto == NATPMP_MAP_TCP) ? map->tcp.private_port : map->udp.private_port;

    return ipc_do(&req);
}

/**
 * Cleans up everything as if NATPMD never touched the system.
 * Returns 0 on success, nonzero on error.
 */
int ipc_req_cleanup(const char *interface, uint16_t min_port, uint16_t max_port) {
    AvahiNatpmdIPCReq req;

    assert(interface);

    memset(&req, '\0', sizeof(req));

    req.op = IPCREQ_OP_CLEANUP;
    strncpy(req.interface, interface, sizeof(req.interface));
    req.interface[sizeof(req.interface)-1] = '\0';
    req.min_port = min_port;
    req.max_port = max_port;

    return ipc_do(&req);
}

/**
 * Executes an IPC request by calling the worker process and returning the
 * result.
 * Return code is one of the NATPMP_RESULT_* values defined in common.h, or -1
 * if something really bad happened and the caller should give up and go home.
 */
int ipc_do(const AvahiNatpmdIPCReq *req) {
    ssize_t ret;
    AvahiNatpmdIPCReq resp;

    assert(req != NULL);

    ret = send(ipc_sock, req, sizeof(*req), 0);

    /* FIXME: Properly handle socket closure (by respawning another worker?)
     * Also handle EINTR/EAGAIN. */

    if (ret < (ssize_t)sizeof(*req)) {
        if (ret == -1)
            daemon_log(LOG_ERR, "IPC send failed: %s", strerror(errno));

        return ret == -1 ? -1 : NATPMP_RESULT_NO_RESOURCES;
    }

    /* ipc_sock has a timeout to prevent this process wedging if the worker
     * never responds */
    ret = recv(ipc_sock, &resp, sizeof(resp), 0);

    if (ret < (ssize_t)sizeof(resp)) {
        if (ret == -1)
            daemon_log(LOG_ERR, "IPC recv failed: %s", strerror(errno));

        return ret == -1 ? -1 : NATPMP_RESULT_NO_RESOURCES;
    }

    return resp.result;
}

/* vim:ts=4:sw=4:et:tw=80
 */
