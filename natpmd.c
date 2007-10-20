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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <avahi-common/malloc.h>
#include <avahi-common/fdutil.h>
#include <avahi-common/llist.h>

#include <avahi-common/setproctitle.h>
#include <avahi-common/ini-file-parser.h>

#include <libdaemon/dfork.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dsignal.h>

#ifndef __linux__
# warning "avahi-natpmd is only designed for Linux at the moment."
# warning "Please let us know if it works on other platforms, though!"
#endif

#include "common.h"
#include "interface.h"
#include "ipc.h"
#include "maplist.h"
#include "natpmd-config.h"
#include "packetdump.h"
#include "timer.h"
#include "worker.h"

/** #defines **/

/* Number of times to try to find an available public port */
#define MAX_PORT_TRIES 100
/* struct timeval {sec, microsec} */
#define SOCKET_TEST_WAIT_TIME   { 0, 20000 } /* 20 msec */
#define IPC_WAIT_TIME           { 4, 0 } /* 4 sec */

#define MAX_MAPPING_LIFETIME    3600U


/** types **/
typedef struct AvahiNPQueueItem AvahiNPQueueItem;

/** A resend queue */
struct AvahiNPQueueItem {
    AVAHI_LLIST_FIELDS(AvahiNPQueueItem, item);
    struct timespec next_time;
    int resends_left;
    AvahiNPPacket *packet;
};


/** function declarations **/
static void avahi_natpm_set_public_addr(AvahiNatpmInterface *iface);
static int send_packet_with_resend(AvahiNPPacket *pkt);
static void avahi_np_send_and_update(AvahiNPQueueItem *item);
static int process_retransmit_queue(void);
static inline uint32_t sssoe(void);
static void map_port(AvahiNPPacket *response, uint32_t lifetime, uint16_t priv_port, uint16_t pub_port, AvahiNPProto proto);
static uint16_t unmap_port(AvahiNPPacket *response, in_addr_t host, uint16_t priv_port, AvahiNPProto proto);
static void process_map_packet(const AvahiNPPacket *request, AvahiNPPacket *response);
static AvahiNatpmMap *find_free_port(uint16_t port_hint);
static int remove_mapping(AvahiNatpmMap *map, AvahiNPProto proto);
static int get_bound_socket(int type, uint16_t port);
static int remove_all_mappings(in_addr_t host, AvahiNPProto proto);
static void expire_maps(void);
static int next_retransmit_time(struct timespec *next_time);
static void update_timer(void);
static void remove_all_mappings_all_hosts(void);

/** globals **/

/** An /unsorted/ list of packets that require timed retransmission */
static AVAHI_LLIST_HEAD(AvahiNPQueueItem, resend_queue_head) = NULL;

time_t epoch;

static AvahiNatpmInterface *public_interface;
static AvahiNatpmPrivateInterface *private_interfaces;
static char *config_filename;
static AvahiNatpmdConfig config;

int ipc_sock = -1;

/* This is defined by protocol section 3.2.1 */
static const struct timespec resend_delays[] = {
    { 0, 0 },
    { 0, 250000000L },
    { 0, 500000000L },
    { 1, 0 },
    { 2, 0 },
    { 4, 0 },
    { 8, 0 },
    { 16, 0 },
    { 32, 0 },
    { 64, 0 }
};

static const char *const proto_strings[] = {
    "?", /* invalid */
    "UDP",
    "TCP"
};

char *argv0 = NULL;
static int daemonize = 0;
static int use_syslog = 0;
#if 0 /* unused */
static int debug = 0;
#endif
static int modify_proc_title = 1;
#ifdef HAVE_CHROOT
static int do_chroot = 1;
#endif
static int wrote_pid_file = 0;

static enum {
    DAEMON_RUN,
    DAEMON_KILL,
    DAEMON_VERSION,
    DAEMON_HELP,
    DAEMON_CHECK
} command = DAEMON_RUN;


/** function implementations **/

static int parse_command_line(int argc, char *argv[]) {
    int c;

    enum {
        OPTION_NO_PROC_TITLE = 256,
        OPTION_DEBUG,
        OPTION_NO_DROP_ROOT,
#ifdef HAVE_CHROOT
        OPTION_NO_CHROOT
#endif
    };

    static const struct option long_options[] = {
        { "help",          no_argument,       NULL, 'h' },
        { "config",        required_argument, NULL, 'f' },
        { "daemonize",     no_argument,       NULL, 'D' },
        { "syslog",        no_argument,       NULL, 's' },
        { "kill",          no_argument,       NULL, 'k' },
        { "check",         no_argument,       NULL, 'c' },
        { "version",       no_argument,       NULL, 'V' },
#ifdef HAVE_CHROOT
        { "no-chroot",     no_argument,       NULL, OPTION_NO_CHROOT },
#endif
        { "no-proc-title", no_argument,       NULL, OPTION_NO_PROC_TITLE },
#if 0 /* unused */
        { "debug",         no_argument,       NULL, OPTION_DEBUG },
#endif
        { NULL, 0, NULL, 0 }
    };

    while ((c = getopt_long(argc, argv, "hDskct:V", long_options, NULL)) >= 0) {
        switch (c) {
            case 'h':
                command = DAEMON_HELP;
                break;

            case 'f':
                avahi_free(config_filename);
                config_filename = avahi_strdup(optarg);
                break;

            case 'D':
                daemonize = 1;
                break;

            case 's':
                use_syslog = 1;
                break;

            case 'k':
                command = DAEMON_KILL;
                break;

            case 'c':
                command = DAEMON_CHECK;
                break;

            case 'V':
                command = DAEMON_VERSION;
                break;

            case OPTION_NO_PROC_TITLE:
                modify_proc_title = 0;
                break;

#if 0 /* unused */
            case OPTION_DEBUG:
                debug = 1;
                break;
#endif

#ifdef HAVE_CHROOT
            case OPTION_NO_CHROOT:
                do_chroot = 0;
                break;
#endif

            default:
                return -1;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "Too many arguments\n");
        return -1;
    }

    return 0;
}

#define set_env(key, value) putenv(avahi_strdup_printf("%s=%s", (key), (value)))

static int drop_privs(void) {
    struct passwd *pw;
    struct group *gr;
    int r;
    mode_t u;
    struct stat st;

    /* Get user/group ID */
    
    if (!(pw = getpwnam(AVAHI_NATPMD_USER))) {
        daemon_log(LOG_ERR, "Failed to find user '"AVAHI_NATPMD_USER"'.");
        return -1;
    }
    
    if (!(gr = getgrnam(AVAHI_NATPMD_GROUP))) {
        daemon_log(LOG_ERR, "Failed to find group '"AVAHI_NATPMD_GROUP"'.");
        return -1;
    }
    
    daemon_log(LOG_INFO, "Found user '"AVAHI_NATPMD_USER"' (UID %lu) and group '"AVAHI_NATPMD_GROUP"' (GID %lu).", (unsigned long) pw->pw_uid, (unsigned long) gr->gr_gid);

    /* Create directory */
    u = umask(0000);
    r = mkdir(AVAHI_NATPMD_CHROOT_DIR, 0755);
    umask(u);
    
    if (r < 0 && errno != EEXIST) {
        daemon_log(LOG_ERR, "mkdir(\""AVAHI_NATPMD_CHROOT_DIR"\"): %s", strerror(errno));
        return -1;
    }

    /* Convey working directory */
    
    chown(AVAHI_NATPMD_CHROOT_DIR, pw->pw_uid, gr->gr_gid);
    
    if (stat(AVAHI_NATPMD_CHROOT_DIR, &st) < 0) {
        daemon_log(LOG_ERR, "stat(): %s\n", strerror(errno));
        return -1;
    }
    
    if (!S_ISDIR(st.st_mode) || st.st_uid != pw->pw_uid || st.st_gid != gr->gr_gid) {
        daemon_log(LOG_ERR, "Failed to create runtime directory "AVAHI_NATPMD_CHROOT_DIR".");
        return -1;
    }

#ifdef HAVE_CHROOT

    if (do_chroot) {
        if (chroot(AVAHI_NATPMD_CHROOT_DIR) < 0) {
            if (geteuid() != 0) {
                daemon_log(LOG_ERR,
                        "Failed to chroot(): %s. You probably need to start %s as root.",
                        strerror(errno), argv0);
            } else {
                daemon_log(LOG_ERR, "Failed to chroot(): %s", strerror(errno));
            }
            return -1;
        }

        daemon_log(LOG_INFO, "Successfully called chroot().");
        chdir("/");

        /* Since we are now trapped inside a chroot we cannot remove
         * the pid file anymore, the helper process will do that for us. */
        wrote_pid_file = 0;
    }
    
#endif

    if (initgroups(AVAHI_NATPMD_USER, gr->gr_gid) != 0) {
        daemon_log(LOG_ERR, "Failed to change group list: %s", strerror(errno));
        return -1;
    }
    
#if defined(HAVE_SETRESGID)
    r = setresgid(gr->gr_gid, gr->gr_gid, gr->gr_gid);
#elif defined(HAVE_SETEGID)
    if ((r = setgid(gr->gr_gid)) >= 0)
        r = setegid(gr->gr_gid);
#elif defined(HAVE_SETREGID)
    r = setregid(gr->gr_gid, gr->gr_gid);
#else
#error "No API to drop privileges"
#endif

    if (r < 0) {
        daemon_log(LOG_ERR, "Failed to change GID: %s", strerror(errno));
        return -1;
    }
    
#if defined(HAVE_SETRESUID)
    r = setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid);
#elif defined(HAVE_SETEUID)
    if ((r = setuid(pw->pw_uid)) >= 0)
        r = seteuid(pw->pw_uid);
#elif defined(HAVE_SETREUID)
    r = setreuid(pw->pw_uid, pw->pw_uid);
#else
#error "No API to drop privileges"
#endif
    
    if (r < 0) {
        daemon_log(LOG_ERR, "Failed to change UID: %s", strerror(errno));
        return -1;
    }

    set_env("USER", pw->pw_name);
    set_env("LOGNAME", pw->pw_name);
    set_env("HOME", pw->pw_dir);
    
    daemon_log(LOG_INFO, "Successfully dropped root privileges.");
    
    return 0;
}

static void help(FILE *file, const char *a0) {
    fprintf(file,
            /* Please keep these options sorted alphabetically */
            "%s [options]\n"
            "    -c --check          Return 0 if a daemon is already running\n"
            "    -D --daemonize      Daemonize after startup\n"
            "    -f --file=FILE      Load the specified configuration file instead of\n"
            "                        " AVAHI_NATPMD_CONFIG_FILE "\n"
            "    -h --help           Show this help\n"
            "    -k --kill           Kill a running daemon\n"
            "    -s --syslog         Write log messages to syslog(3) instead of STDERR\n"
            "    -t --script=SCRIPT  Action script to run (defaults to\n"
            "                        " AVAHI_NATPMD_ACTION_SCRIPT ")\n"
            "    -V --version        Show version\n"
#if 0 /* unused */
            "       --debug          Increase verbosity\n"
#endif
#ifdef HAVE_CHROOT
            "       --no-chroot      Don't chroot()\n"
#endif
            "       --no-proc-title  Don't modify the process title\n",
            a0);
}


/* Creates the NATPMD network socket and binds it as necessary. */
static int pmdsock(void) {
    int sock;
    struct sockaddr_in sin;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        daemon_log(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(NATPMP_PORT);
    /* FIXME: Be more intelligent about which interface(s) to bind */
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        daemon_log(LOG_ERR, "bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* FIXME: Set the multicast interface (IP_MULTICAST_IF). */
    /* XXX: Any use setting IP_MULTICAST_LOOP? */

    return sock;
}

uint32_t sssoe(void) {
    return time(NULL) - epoch;
}

/* TODO: Make this do lots of things like clear the notification queue, send
 * a reset state packet, delete all port forwards, ... */
void avahi_natpm_set_public_addr(AvahiNatpmInterface *iface) {

    if (public_interface)
        avahi_natpm_free_interface(public_interface);

    public_interface = iface;

    epoch = time(NULL);

    if (iface) {
        daemon_log(LOG_INFO, "%s: Set public interface to %s",
                __FUNCTION__, iface->name);
    } else {
        daemon_log(LOG_INFO, "%s: Unset public interface", __FUNCTION__);
    }
}

static inline void prepare_response(const AvahiNPPacket *query, AvahiNPPacket *response) {
    memset(response, 0, sizeof(*response));
    response->sock = query->sock;
    response->addr = query->addr;
    response->ever_sent = 0;
    response->datalen = 0; /* canary */
    response->data.common.version = 0;
    response->data.common.opcode = query->data.common.opcode | NATPMP_PKT_OP_FLAG_RESPONSE;
    response->data.common.result = NATPMP_RESULT_CANARY;
    /* Don't set the real sssoe here. The actual operation (particularly a
     * port mapping callout) could take some time, and by the time the
     * packet actually goes out, the SSSOE could be misleading */
    response->data.u32[1] = htonl(NATPMP_TIME_CANARY);
}

/**
 * Send a packet onto the network.
 * You should use send_packet_once() or send_packet_with_resend() instead.  
 * (They call this. You are not allowed to.)
 * @param pkt The packet to be sent. The packet's SSSOE field will be set the
 *            first time it is passed to this function.
 */
static void send_packet(AvahiNPPacket *pkt) {
    int flags = 0;

    assert(pkt);
    assert(pkt->sock >= 0);

    /* Minimum response is ver + op + result */
    assert(pkt->datalen >= 4);
    assert(pkt->datalen <= 16);
    assert(pkt->data.common.result != NATPMP_RESULT_CANARY);

    pkt->data.u32[1] = htonl(sssoe());

#if 0 /* noisy */
# if 1 /* efficient */
    daemon_log(LOG_DEBUG, "Sending packet to %s: opcode[%hhu] result[%hu] ever_sent[%d]",
            ip4_addr_str(pkt->addr.sin_addr), pkt->data.common.opcode, pkt->data.common.result,
            pkt->ever_sent);
# else /* ridiculously inefficient, but detailed */
    daemon_log(LOG_DEBUG, "Sending packet %s", avahi_natpmp_pkt_dump(pkt));
    avahi_natpmp_pkt_dump_free();
# endif
#endif

    pkt->ever_sent = 1;

#ifdef MSG_CONFIRM
    flags |= MSG_CONFIRM;
#endif
    /* NAT-PMP only works when the gateway is the NAT device anyway */
    flags |= MSG_DONTROUTE;

    if (sendto(pkt->sock, &pkt->data, pkt->datalen, flags, (const struct sockaddr*)&pkt->addr, sizeof(pkt->addr)) == -1)
        daemon_log(LOG_ERR, "Sending response packet failed: %s", strerror(errno));

    /* TODO: We should also be checking MSG_ERRQUEUE using recvmsg for things
     * like ICMP Port Unreachable to cancel message resends.
     * This is not the place to do it, but I had to write it down somewhere. */
}

static void prepare_public_ip_notification(AvahiNPPacket *p) {
    p->data.common.opcode = NATPMP_OPCODE_PUBLIC_ADDR | NATPMP_PKT_OP_FLAG_RESPONSE;
    p->datalen = 12;

    if (!public_interface) {
        /* Public address MUST be zero for failure packets.
         * Fortunately it already is. */
        p->data.common.result = htons(NATPMP_RESULT_NETWORK_FAILURE);
        return; /* ok */
    }

    p->data.common.result = htons(NATPMP_RESULT_SUCCESS);
    /* SSSOE will be set by send_packet() */
    p->data.u32[2] = public_interface->address;
}

/**
 * Turn a portmap request packet into a string for use in log output.
 * @return A pointer to static storage that will be overwritten on subsequent
 *         calls.
 *
 * XXX: Fold this into packetdump.c
 */
static const char *portmap_request_to_str(const AvahiNPPacket *pkt) {
    /* Dynamic memory allocation is for wimps ;)
     * I love doing this kind of thing... */
    static char desc[sizeof("host[255.255.255.255] prot[TCP] pub[65535] priv[65535] life[4294967295]")];
    AvahiNPProto proto;

    assert(pkt);

    proto = pkt->data.common.opcode;
    assert(proto == NATPMP_OPCODE_MAP_TCP ||
           proto == NATPMP_OPCODE_MAP_UDP);

    (void)snprintf(desc, sizeof(desc), "host[%.15s] prot[%.3s] pub[%hu] priv[%hu] life[%u]",
            ip4_addr_str(pkt->addr.sin_addr),
            proto_strings[proto],
            ntohs(pkt->data.u16[3]),
            ntohs(pkt->data.u16[2]),
            ntohl(pkt->data.u32[2]));

    return desc;
}

/**
 * Processes a map request packet (which may be a delete mapping request).
 * Fills in the response packet which is to be sent by the caller.
 */
static void process_map_packet(const AvahiNPPacket *request, AvahiNPPacket *response) {
    AvahiNPProto proto;
    uint32_t lifetime;
    uint16_t priv_port, pub_port;

    lifetime = ntohl(request->data.u32[2]);
    priv_port = ntohs(request->data.u16[2]);
    pub_port = ntohs(request->data.u16[3]);
    proto = request->data.u8[1];

    response->data.u16[4] = htons(priv_port);
    response->data.u16[5] = htons(pub_port);
    response->data.u32[3] = htonl(lifetime); /* Requested lifetime */
    response->datalen = 16;

    if (!public_interface) {
        daemon_log(LOG_INFO, "Received a map request, but the public interface is unknown, responding with network failure.");
        response->data.common.result = htons(NATPMP_RESULT_NETWORK_FAILURE);
        return;
    }

    /* Santitise input */

    /* Proto has already been sanitised by caller. */
    assert(proto == NATPMP_OPCODE_MAP_TCP || proto == NATPMP_OPCODE_MAP_UDP);

    if (lifetime)
        daemon_log(LOG_INFO, "Trying to fulfill port mapping request (%s)", portmap_request_to_str(request));
    else
        daemon_log(LOG_INFO, "Trying to fulfill port unmapping request (%s)", portmap_request_to_str(request));

    if (lifetime > MAX_MAPPING_LIFETIME)
        lifetime = MAX_MAPPING_LIFETIME;

    if (lifetime == NATPMP_TIME_CANARY)
        --lifetime;

    response->data.u32[3] = htonl(lifetime); /* Allocated lifetime */

    if (lifetime == 0)
        unmap_port(response, request->addr.sin_addr.s_addr, priv_port, proto);
    else
        map_port(response, lifetime, priv_port, pub_port, proto);

    /* response is sent by caller */
}

/**
 * Ensures a packet is only sent once.
 * Mainly exists to catch programmer errors.
 */
static inline void send_packet_once(AvahiNPPacket *pkt) {
    assert(pkt);
    assert(pkt->ever_sent == 0);

    send_packet(pkt);
}

/**
 * Process an incoming packet, and respond.
 */
static void process_packet(const AvahiNPPacket *pkt) {
    const struct in_addr inaddr = pkt->addr.sin_addr;
    AvahiNPPacket response;

    if (pkt->datalen < NATPMP_MINPKTSIZE)
        daemon_log(LOG_INFO, "Received a packet that was too small (%d bytes) from %s", pkt->datalen, ip4_addr_str(inaddr));

    /* TODO: Update this to compare against private_interfaces once that is
     * implemented. */
    if (avahi_natpm_address_visibility(inaddr.s_addr) != AVAHI_NATPM_ADDRESS_VISIBILITY_PRIVATE &&
            avahi_natpm_address_visibility(inaddr.s_addr) != AVAHI_NATPM_ADDRESS_VISIBILITY_LOOPBACK) {
        daemon_log(LOG_INFO, "Ignoring packet from non-private address %s",
                ip4_addr_str(inaddr));
        return;
    }
    
    if (   pkt->data.common.version == 0
        && pkt->data.common.opcode & NATPMP_PKT_OP_FLAG_RESPONSE) {
        /* Not at all interested in response packets. Return early to avoid
         * noisy logging caused by response packets (which were usually
         * generated by us anyway) */
        return;
    }

    daemon_log(LOG_DEBUG, "Processing packet %s", avahi_natpmp_pkt_dump(pkt));

    prepare_response(pkt, &response);

    if (pkt->data.common.version != 0) {
        daemon_log(
                LOG_INFO,
                "Received a packet with unknown protocol version %hhu from %s",
                pkt->data.common.version,
                ip4_addr_str(inaddr));
        response.data.common.result = htons(NATPMP_RESULT_UNSUPPORTED_VERSION);
        response.datalen = 4;
        send_packet_once(&response);
        return;
    }

    switch (pkt->data.common.opcode) {
        case NATPMP_OPCODE_PUBLIC_ADDR:
            prepare_public_ip_notification(&response);
            send_packet_once(&response);
            return;

        case NATPMP_OPCODE_MAP_UDP: /* fall through */
        case NATPMP_OPCODE_MAP_TCP:
            process_map_packet(pkt, &response);
            send_packet_once(&response);
            return;

        default:
            daemon_log(LOG_INFO, "Received a packet with an unrecognised opcode %hhu from %s", pkt->data.common.opcode,
                    ip4_addr_str(inaddr));
            response.data.common.result = htons(NATPMP_RESULT_UNSUPPORTED_OPCODE);
            response.datalen = 4;
            send_packet_once(&response);
            return;
    }

    /* not reached */
    assert(0);
}

/**
 * Find a free port and map it.
 * This should not be used if the host already has the other of the TCP/UDP pair
 * mapped on the requested port number.
 * @param   port_hint   Preferred public port.
 * @return              Returns an AvahiNatpmMap structure, or NULL if no
 *                      available public port could
 *                      be found. The returned structure has _not_ been added to
 *                      the mapping list and only its local_bind.* and
 *                      public_port members have been initialised.
 */
AvahiNatpmMap *find_free_port(uint16_t port_hint) {
    AvahiNatpmMap *map = NULL;
    int stcp = -1, sudp = -1;
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);
    int i;
    uint16_t udp_port = 0, tcp_port = 0;
    static uint16_t last_port = 0; /* Provides a hint for the next sequential port to try */

    if (port_hint < config.min_port || port_hint > config.max_port) {
        daemon_log(LOG_DEBUG, "%s: port_hint %hu outside the configured range of %hu to %hu",
                __FUNCTION__, port_hint, config.min_port, config.max_port);
        port_hint = 0;
    }

    /* This algorithm is possibly inefficient partly because it is sequential
     * and partly because it walks the maplist on every try.
     * Refer to my crazy (yet deterministic) port selection algorithm for
     * a partial alternative. -tp */

    for (i = 0; i < MAX_PORT_TRIES; ++i) {

        if (port_hint == 0) {
            /* It does not matter if port values overflow back to zero */
            ++last_port;

            if (last_port < config.min_port || last_port > config.max_port)
                last_port = config.min_port;

            port_hint = last_port;
        }

        daemon_log(LOG_DEBUG,
                "%s: Trying to find a free port (port_hint == %hu, attempt %d of %d)",
                __FUNCTION__, port_hint, i + 1, MAX_PORT_TRIES);

        /* See if this port is already mapped */
        map = avahi_natpm_maplist_find_by_pub_port(port_hint);
        if (map) {
            daemon_log(LOG_DEBUG, "%s: Port %hu is already mapped",
                    __FUNCTION__, port_hint);
            port_hint = 0;
            continue; /* Try again */
        }

        /* TCP is more likely to be unavailable, so try it first */
        stcp = get_bound_socket(SOCK_STREAM, port_hint);
        if (stcp < 0) {
            if (stcp == -2) {
                daemon_log(LOG_NOTICE,
                        "%s: get_bound_socket() indicated that the system has run out of available ports. Giving up.",
                        __FUNCTION__);
                goto fail;
            }

            port_hint = 0;
            continue; /* Try again */
        }

        /* Find out what port was actually found */

        /* Make sure we try the same port that was returned for TCP */
        if (getsockname(stcp, (struct sockaddr *)&sin, &sinlen) == -1) {
            daemon_log(LOG_ERR, "%s: getsockname(stcp) failed: %s", __FUNCTION__, strerror(errno));
            goto fail;
        }

        tcp_port = ntohs(sin.sin_port);
        
        sudp = get_bound_socket(SOCK_DGRAM, tcp_port);
        if (sudp < 0) {
            close(stcp);
            stcp = -1;

            if (sudp == -2) {
                daemon_log(LOG_NOTICE,
                        "%s: get_bound_socket() indicated that the system has run out of available ports. Giving up.",
                        __FUNCTION__);
                goto fail;
            }

            port_hint = 0;
            continue;
        }
        
        udp_port = tcp_port;

        break;
    }

    if (sudp == -1 || stcp == -1) {
        daemon_log(LOG_NOTICE, "%s: Unable to find a free port after %d tries", __FUNCTION__, MAX_PORT_TRIES);
        goto fail;
    }

#if 0
    /* Just to be sure, check that the UDP port is the same as the TCP port */
    sinlen = sizeof(sin);
    if (getsockname(sudp, (struct sockaddr*)&sin, &sinlen) == -1) {
        daemon_log(LOG_ERR, "%s: getsockname() failed for UDP socket", __FUNCTION__);
        goto fail;
    }

    udp_port = ntohs(sin.sin_port);

    if (udp_port != tcp_port) {
        daemon_log(LOG_CRIT, "%s: TCP port (%hu) does not match UDP port (%hu). "
                "This does not make sense, so I'm giving up.",
                __FUNCTION__, tcp_port, udp_port);
        goto fail;
    }
#endif

    /* Map succeeded */
    daemon_log(LOG_INFO, "%s: Found free port %hu", __FUNCTION__, udp_port);

    map = avahi_new0(AvahiNatpmMap, 1);
    if (!map)
        goto fail;

    map->public_port = tcp_port;
    map->tcp.sock = stcp;
    map->udp.sock = sudp;

    return map;

fail:
    if (stcp != -1)
        close(stcp);
    if (sudp != -1)
        close(sudp);
    if (map)
        avahi_free(map);

    return NULL;
}

/**
 * Tries to create, bind and return a socket of the chosen type. It will be
 * bound to the chosen port on the current public interface.
 * This function will only try the chosen port if port is nonzero. It will not
 * attempt to find another free port.
 *
 * @param  type  SOCK_STREAM for TCP or SOCK_DGRAM for UDP
 * @param  port  port number (host byte order)
 *               in the range min_port <= port <= max_port.
 * @return       a socket that is bound to the port if it is (was) free, -1
 *               if the port is unavailable, and -2 if some major error occurred
 *               (like there are no sockets available) and the caller should not
 *               try again.
 */
static int get_bound_socket(int type, uint16_t port) {
    int sock = -1;
    struct sockaddr_in sin;
    int failreturn = -1;
    struct timeval wait = SOCKET_TEST_WAIT_TIME;

    /* XXX: This function needs better logging for errors.
     * It would be worth consolidating all the generic socket errors into a
     * single error message. */

    assert(type == SOCK_STREAM || type == SOCK_DGRAM);
    assert(port >= config.min_port);
    assert(port <= config.max_port);
    assert(public_interface != NULL);

    if ((sock = socket(PF_INET, type, 0)) == -1)
        goto permfail;

    /* XXX: Should this be fatal? */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait)) == -1)
        daemon_log(LOG_WARNING, "%s: Failed to set socket timeout: %s",
                __FUNCTION__, strerror(errno));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = public_interface->address;

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        if (errno == EADDRINUSE) {
            daemon_log(LOG_DEBUG, "%s: bind() failed: %s", __FUNCTION__, strerror(errno));
            goto fail;
        }

        daemon_log(LOG_ERR, "%s: bind() failed: %s", __FUNCTION__, strerror(errno)); 
        goto permfail;
    }

    if (port == 0) {
        /* Find out what port is actually bound */
        socklen_t slen = sizeof(sin);
        if (getsockname(sock, (struct sockaddr *)&sin, &slen) == -1) {
            daemon_log(LOG_ERR, "%s: getsockname() failed: %s", __FUNCTION__, strerror(errno));
            goto permfail;
        }
        port = ntohs(sin.sin_port);
    }

    /* Port works fine */
    daemon_log(LOG_DEBUG, "%s: %s port %hu seems to work fine",
            __FUNCTION__, type == SOCK_STREAM ? "TCP" : "UDP", port);

    return sock;

permfail: /* Permanent failure, caller should not try again immediately */
    failreturn = -2;

fail:
    if (sock >= 0)
        close(sock);

    return failreturn;
}

/**
 * Removes a mapping. Does not send any NAT-PMP packets.
 * @param   map     The mapping to remove.
 * @param   proto   The protocol to act on.
 * @return          NATPMP protocol result code or -1 if the IPC request failed.
 */
static int remove_mapping(AvahiNatpmMap *map, AvahiNPProto proto) {
    struct per_proto *per_proto;

    assert(map != NULL);

    if (proto == NATPMP_MAP_TCP)
        per_proto = &map->tcp;
    else
        per_proto = &map->udp;

    per_proto->state = PORT_UNMAPPED;

    return ipc_req_remove(map, proto);
}

/**
 * Sets the mapping expiry for the specified map structure and the given
 * protocol to now + lifetime. Also updates the global timer.
 */
static void set_map_lifetime(AvahiNatpmMap *map, AvahiNPProto proto, uint32_t lifetime) {
    const time_t expiry = time(NULL) + lifetime;

    assert(map != NULL);

    if (proto == NATPMP_MAP_TCP)
        map->tcp.expiry = expiry;
    else
        map->udp.expiry = expiry;

    if (expiry < avahi_natpm_maplist_next_expiration()
        || avahi_natpm_maplist_next_expiration() == -1) {

        daemon_log(LOG_DEBUG, "%s: Updating next timer expiry to %ld",
                __FUNCTION__, expiry);

        timer_notify_expiry(expiry);
    }
}

/**
 * Tries to fulfill a client request to map a port.
 * Always returns a valid packet that should be sent to the client.
 * @param   response    [in,out] Must have some fields populated, including the
 *                       remote address.
 */
void map_port(AvahiNPPacket *response, uint32_t lifetime, uint16_t priv_port, uint16_t pub_port, AvahiNPProto proto) {
    AvahiNatpmMap *map = NULL;
    int other_proto_already_mapped = 0;

    assert(response);
    assert(lifetime != 0);
    assert(lifetime != NATPMP_TIME_CANARY);

    /* The spec does not specify what to do when priv_port == 0. */
    if (priv_port == 0) {
        daemon_log(LOG_NOTICE, "Client %s tried to map to private port 0. Not allowing that.",
                ip4_addr_str(response->addr.sin_addr));
        response->data.common.result = htons(NATPMP_RESULT_REFUSED);
        goto fail;
    }

    daemon_log(LOG_DEBUG, "%s: Received mapping request from %s for private port %hu and public port %hu",
            __FUNCTION__, ip4_addr_str(response->addr.sin_addr), priv_port, pub_port);

    /* Check if this host already has this port mapped (regardless of proto) */
    map = avahi_natpm_maplist_find_hostport(response->addr.sin_addr.s_addr, priv_port);
    if (map) {
        if ((proto == NATPMP_MAP_TCP && map->tcp.state == PORT_MAPPED)
                || (proto == NATPMP_MAP_UDP && map->udp.state == PORT_MAPPED)) {

            daemon_log(LOG_DEBUG, "%s: Mapping already active, updating lifetime and sending success.",
                    __FUNCTION__);

            set_map_lifetime(map, proto, lifetime);

            response->data.common.result = htons(NATPMP_RESULT_SUCCESS);
            return;
        }
        /* else: map other proto (continue below) */
        other_proto_already_mapped = 1;

    } else {
        /* New mapping required */
        map = find_free_port(pub_port);

        if (!map) {
            daemon_log(LOG_DEBUG,
                    "%s: No free port found. Sending failure packet.",
                    __FUNCTION__);

            response->data.common.result = htons(NATPMP_RESULT_NO_RESOURCES);
            goto fail;
        }

        /* Fill in more of the map struct */
        map->private_addr = response->addr.sin_addr.s_addr;
    }

    if (proto == NATPMP_MAP_TCP)
        map->tcp.private_port = priv_port;
    else
        map->udp.private_port = priv_port;

    set_map_lifetime(map, proto, lifetime);

    pub_port = map->public_port;
    response->data.u16[5] = htons(pub_port);

    if (ipc_req_add(map, proto) != 0) {
        daemon_log(LOG_INFO, "%s: IPC request failed", __FUNCTION__);
        remove_mapping(map, proto);
        response->data.common.result = htons(NATPMP_RESULT_NO_RESOURCES);
        goto fail;
    }

    daemon_log(LOG_DEBUG, "%s: Port successfully mapped by iptables", __FUNCTION__);

    /* Only set the mapped state after nothing else can go wrong. */
    if (proto == NATPMP_MAP_TCP)
        map->tcp.state = PORT_MAPPED;
    else
        map->udp.state = PORT_MAPPED;

    if (!other_proto_already_mapped)
        avahi_natpm_maplist_add(map);

    daemon_log(LOG_INFO, "Successfully mapped lifetime[%u], private[%hu], public[%hu], proto[%s] for [%s]",
            lifetime, priv_port, pub_port, proto_strings[proto], ip4_addr_str(response->addr.sin_addr));

    response->data.common.result = htons(NATPMP_RESULT_SUCCESS);

    return;

fail:
    if (map && !other_proto_already_mapped)
        avahi_natpm_map_destroy(map);

    /* If other_proto_already_mapped then this proto's state is still
     * safely PORT_UNMAPPED. */
    /* It doesn't matter if the timer fires a blank because of this failure --
     * don't bother updating it. */
}

void remove_all_mappings_all_hosts(void) {
    const AvahiNatpmMap *map;
    int sndsock;

    sndsock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sndsock == -1) {
        daemon_log(LOG_ERR, "%s: Error creating socket: %s",
                __FUNCTION__, strerror(errno));
        return;
    }

    while ((map = avahi_natpm_maplist_peek())) {
        int proto;
        int retcode;
        AvahiNPPacket pkt;

        /* Don't refer to the map variable after calling another maplist
         * function -- that map will probably have been freed! */

        if (map->tcp.state == PORT_MAPPED) {
            proto = NATPMP_PROTO_TCP;
        } else {
            assert(map->udp.state == PORT_MAPPED);
            proto = NATPMP_PROTO_UDP;
        }

        memset(&pkt, '\0', sizeof(pkt));
        pkt.sock = sndsock;
        pkt.addr.sin_family = AF_INET;
        pkt.addr.sin_addr.s_addr = map->private_addr;
        pkt.addr.sin_port = htons(NATPMP_PORT);
        pkt.datalen = 12;
        pkt.data.common.version = 0;
        pkt.data.common.opcode = proto | NATPMP_PKT_OP_FLAG_RESPONSE;

        retcode = remove_all_mappings(map->private_addr, proto);

        map = NULL; /* Was probably freed during remove_all_mappings() */

        if (retcode >= 0 && retcode < UINT16_MAX) {
            pkt.data.common.result = retcode;
            send_packet_once(&pkt);
        } else {
            daemon_log(LOG_WARNING,
                    "%s: Not sending an unmap notification to %s "
                    "because remove_all_mappings returned %d",
                    __FUNCTION__, ip4_addr_str(pkt.addr.sin_addr),
                    retcode);
        }
    }

    do errno = 0;
    while (close(sndsock) == -1 && errno == EINTR);

    if (errno) {
        daemon_log(LOG_ERR, "%s: close() failed: %s",
                __FUNCTION__, strerror(errno));
    }
}

/**
 * Removes all the TCP or UDP mappings of a particular host.
 * Returns a NAT-PMP result code, or -1 if something went horribly wrong.
 */
int remove_all_mappings(in_addr_t host, AvahiNPProto proto) {
    AvahiNatpmMap **results; /* Array of pointers */
    int nres, i;
    int retcode = NATPMP_RESULT_SUCCESS;

    nres = avahi_natpm_maplist_find_byhost(host, &results);
    if (nres < 1)
        return nres;

    for (i = 0; i < nres; ++i) {
        struct per_proto *this_proto, *other_proto;
        if (proto == NATPMP_MAP_TCP) {
            this_proto = &results[i]->tcp;
            other_proto = &results[i]->udp;
        } else {
            this_proto = &results[i]->udp;
            other_proto = &results[i]->tcp;
        }

        if (this_proto->state == PORT_MAPPED) {
            int ret;
            ret = remove_mapping(results[i], proto);
            /* Only propogate the first error, it's most likely to indicate the
             * real cause. */
            if (ret != NATPMP_RESULT_SUCCESS && retcode == NATPMP_RESULT_SUCCESS)
                retcode = ret;

            this_proto->state = PORT_UNMAPPED;

            if (other_proto->state == PORT_UNMAPPED)
                avahi_natpm_maplist_remove(results[i]);
        }
    }

    avahi_natpm_maplist_free_result(results);

    /* Don't remove the timer -- the resend code might need to trigger. */

    return retcode;
}

/**
 * Tries to fulfill a client request to unmap one or several ports.
 * Always returns a valid packet that should be sent to the client.
 * @param response  Packet to which the response info will be written. May be
 *                  NULL.
 * @param host      The host whose port will be unmapped.
 * @return          A NAT-PMP protocol response code
 *                  The same response code will be set in the
 *                  response parameter if it is given.
 */
uint16_t unmap_port(AvahiNPPacket *response, in_addr_t host, uint16_t priv_port, AvahiNPProto proto) {
    struct per_proto *this_proto, *other_proto;
    uint16_t result_code;

    if (priv_port == 0) {
        result_code = remove_all_mappings(host, proto);
    } else {
        /* Client wants to remove this specific mapping */
        AvahiNatpmMap *map;
        /* This is only here because the ip4_addr_str() interface is broken. */
        const struct in_addr saddr = { host };

        map = avahi_natpm_maplist_find_hostportproto(host, priv_port, proto);

        if (map) {

            if (proto == NATPMP_MAP_TCP) {
                this_proto = &map->tcp;
                other_proto = &map->udp;
            } else {
                this_proto = &map->udp;
                other_proto = &map->tcp;
            }

            result_code = remove_mapping(map, proto);
            this_proto->state = PORT_UNMAPPED;

            if (other_proto->state == PORT_UNMAPPED)
                (void) avahi_natpm_maplist_remove(map);

            daemon_log(LOG_INFO, "Unmapped %s private[%hu] for %s",
                    proto_strings[proto], priv_port, ip4_addr_str(saddr));
        } else {
            /* Must send success even if no match was found, because it's probably a
             * retransmission after a missed response (spec 3.4) */
            daemon_log(LOG_INFO, "Returning success for unmap request for "
                    "unknown map [%s:%hu]", ip4_addr_str(saddr), priv_port);
            result_code = NATPMP_RESULT_SUCCESS;
        }
    }

    if (response)
        response->data.common.result = htons(result_code);

    return result_code;
}

/**
 * Remove any maps that have expired.
 * The spec doesn't say anything about whether a notification of unmapping
 * should be sent, so I guess we just do it silently.
 */
void expire_maps(void) {
    AvahiNatpmMap **results;
    int res, i;
    const time_t now = time(NULL);

    res = avahi_natpm_maplist_find_expired(&results);
    
    for (i = 0; i < res; ++i) {
        AvahiNatpmMap *map = results[i];

        /* No packet is sent when a map expires */

        if (map->tcp.state == PORT_MAPPED && map->tcp.expiry <= now) {
            /* daemon_log(LOG_DEBUG, ...); */
            unmap_port(NULL, results[i]->private_addr, map->tcp.private_port, NATPMP_PROTO_TCP);
        }

        if (map->udp.state == PORT_MAPPED && map->udp.expiry <= now) {
            /* daemon_log(LOG_DEBUG, ...); */
            unmap_port(NULL, results[i]->private_addr, map->udp.private_port, NATPMP_PROTO_UDP);
        }
    }

    if (res > 0)
        avahi_natpm_maplist_free_result(results);
}

/* It might be nice to use Glib's main loop for this one day.
 */
static void mainloop(int sock) {
    enum {
        FD_NET,
        FD_SIGNAL,
        FD_MAX
    };
    struct pollfd pfds[FD_MAX];
    int signalfd = -1;
    int keep_going = 1;
    /* Names for identifying the pollfd sockets in log messages */
    static const char *const fdnames[] = { "main", "signal" };

    assert(sock >= 0);

    if ((signalfd = daemon_signal_fd()) < 0) {
        daemon_log(LOG_ERR, "Problem getting signal watcher file descriptor");
        goto end;
    }

    pfds[FD_NET].fd = sock;
    pfds[FD_NET].events = POLLIN;
    pfds[FD_NET].revents = 0;

    pfds[FD_SIGNAL].fd = signalfd;
    pfds[FD_SIGNAL].events = POLLIN;
    pfds[FD_SIGNAL].revents = 0;

    while (keep_going) {
        int pr = poll(pfds, FD_MAX, -1);
        socklen_t fromlen;
        AvahiNPPacket pkt;
        const short badevents = POLLERR | POLLHUP | POLLNVAL;
        int i;

        memset(&pkt, 0, sizeof(pkt));
        
        if (pr == -1) {
            if (errno == EINTR)
                continue;

            daemon_log(LOG_ERR, "mainloop poll() failed: %s", strerror(errno));
            goto end;
        }

        /* This whole "bail" thing is kind of nasty. I'd like to log errors, though */
        for (i = 0; i < FD_MAX; ++i) {
            if (pfds[i].revents & badevents) {
                keep_going = 0;
                daemon_log(LOG_ERR, "Got a bad event (%hd) on %s socket during poll()", pfds[i].revents, fdnames[i]);
                break;
            }
        }
        if (!keep_going)
            break;

        if (pfds[FD_NET].revents & POLLIN) {
            /* Incoming network packets */

            fromlen = sizeof(pkt.addr);

            pkt.datalen = recvfrom(pfds[FD_NET].fd, &pkt.data, sizeof(pkt.data), 0, (struct sockaddr*)&pkt.addr, &fromlen);
            if (pkt.datalen == -1) {
                if (errno == EINTR) {
                    daemon_log(LOG_DEBUG, "recvfrom() was interrupted by a signal. continuing.");
                    continue;
                }
                daemon_log(LOG_ERR, "recvfrom() returned -1: %s", strerror(errno));
                break;
            }

            if (pkt.datalen < NATPMP_MINPKTSIZE) {
                daemon_log(
                        LOG_INFO,
                        "Received a packet that was only %d bytes long (expected at least %d)",
                        pkt.datalen,
                        NATPMP_MINPKTSIZE);
                continue;
            }

            pkt.sock = pfds[FD_NET].fd;

            process_packet(&pkt);
        } /* packet received */

        if (pfds[FD_SIGNAL].revents & POLLIN) {
            /* Signal was delivered */
            int sig;

            sig = daemon_signal_next();

            switch (sig) {
                case SIGALRM:
                    if (avahi_natpm_maplist_has_expired_items())
                        expire_maps();
                    process_retransmit_queue();
                    update_timer();
                    break;

                case SIGINT: /* fall through */
                case SIGTERM:
                    keep_going = 0;
                    daemon_log(LOG_INFO, "Received %s, exiting gracefully",
                            sig == SIGINT ? "SIGINT" : "SIGTERM");
                    break;

                default:
                    daemon_log(LOG_NOTICE, "Received unexpected signal %d from libdaemon", sig);
            }
        } /* signal received */
    } /* while (keep_going) */

    remove_all_mappings_all_hosts();

end:
    if (signalfd >= 0) {
        close(signalfd);
        daemon_signal_done();
    }
}

/**
 * Updates the timer, taking into account packets requiring retransmissions and
 * maps that are going to expire.
 */
void update_timer(void) {
    struct timespec next_retrans;
    time_t exp;
    
    exp = avahi_natpm_maplist_next_expiration();

    if (next_retransmit_time(&next_retrans) != 0) {
        time_t next_retrans_sec;

#if 0 /* noisy */
        daemon_log(LOG_DEBUG, "%s: next retransmit time is %ld (and %ld nsec)",
                __FUNCTION__, next_retrans.tv_sec, next_retrans.tv_nsec);
#endif

        /* XXX: We ignore partial seconds from the
         * retransmission list for simplicity. It's bad.
         * Adding one to make sure we don't fire a bit too
         * early and end up doing nothing */
        next_retrans_sec = next_retrans.tv_sec;
        if (next_retrans.tv_nsec > 0)
            ++next_retrans_sec;

        if (exp == -1 || next_retrans_sec < exp)
            exp = next_retrans_sec;
    }
    timer_notify_expiry(exp);
}

/**
 * Main daemon processing.
 *
 * Returns -1 on failure or 0 on success.
 * Could probably return different codes depending on what went wrong, which
 * could be used as process return codes. */
static int go_daemon(void) {
    int ret = -1;
    int fds[2] = {-1, -1};
    pid_t pid;
    int pmd_listen_sock = -1;

    if (-1 == access(config.mapping_script, R_OK | X_OK)) {
        daemon_log(LOG_ERR,
                "natpmd action script %s is not readable and executable: %s",
                config.mapping_script, strerror(errno));
        goto finish;
    }

    if (-1 == socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds)) {
        daemon_log(LOG_ERR, "Failed to create IPC socket: %s", strerror(errno));
        goto finish;
    }

    if (daemonize) {
        /* Fork and exit the parent process to return it to a shell */
        pid = daemon_fork();
        if (-1 == pid) {
            daemon_log(LOG_ERR, "Failed to fork daemon: %s", strerror(errno));
            goto finish;
        }
        if (pid != 0) {
            /* Parent */
            ret = 0;
            goto finish;
        }
        /* Child continues */
    }

    wrote_pid_file = !daemon_pid_file_create();

    daemon_log(LOG_DEBUG, "%s: Main process running with pid %d",
            __FUNCTION__, getpid());

    pid = daemon_fork();
    if (-1 == pid) {
        daemon_log(LOG_ERR, "Failed to fork daemon: %s", strerror(errno));
        goto finish;
    }

    if (pid == 0) { /* child */
        close(fds[0]);
        ipc_sock = fds[1];
        ret = worker(config.mapping_script, ipc_sock);
    }
    else { /* parent */
        const struct timeval waittime = IPC_WAIT_TIME;
        int first = 1;
        int err;

        close(fds[1]);
        ipc_sock = fds[0];

        if (setsockopt(ipc_sock, SOL_SOCKET, SO_RCVTIMEO, &waittime, sizeof(waittime)) == -1 ||
                (first = 0) ||
                setsockopt(ipc_sock, SOL_SOCKET, SO_SNDTIMEO, &waittime, sizeof(waittime)) == -1) {
            daemon_log(LOG_ERR, "Unable to set %s timeout on IPC socket: %s",
                    first ? "receive" : "send", strerror(errno));
            goto finish;
        }

        (void) avahi_natpm_maplist_init();
        
        /* read config */
        /* ... */
        /* XXX: I would expect that once I have cool interface state shiznit
         * happening, that this will be unnecessary */
        avahi_natpm_set_public_addr(avahi_natpm_get_public_interface_auto());
        if (!public_interface) {
            daemon_log(LOG_ERR, "Could not find a suitable public interface");
            goto finish;
        }

        err = avahi_natpm_get_private_interfaces(&private_interfaces);
        if (err == -1) {
            daemon_log(LOG_ERR, "Failed to get private interfaces");
            goto finish;
        }
        if (err == 0 && private_interfaces == NULL) {
            daemon_log(LOG_ERR, "Insufficient private interfaces");
            goto finish;
        }

        if (modify_proc_title) {
#ifdef HAVE_CHROOT
            avahi_set_proc_title(argv0, "%s: running%s [%s]", argv0,
                    do_chroot ? " (chrooted)" : "", public_interface->name);
#else
            avahi_set_proc_title(argv0, "%s: running [%s]", argv0, public_interface->name);
#endif
        }

        if (drop_privs() < 0)
            goto finish;

        ipc_req_prepare(public_interface->name, config.min_port, config.max_port);

        pmd_listen_sock = pmdsock();
        if (pmd_listen_sock == -1)
            goto finish;

        /* Ensure the SIGALRM handler is installed before any packets are sent */
        if (daemon_signal_init(SIGALRM, SIGINT, SIGTERM, 0) != 0) {
            daemon_log(LOG_ERR, "daemon_signal_init(SIGALRM, SIGINT, SIGTERM) failed");
            goto finish;
        }

        /* Gratuitous address notification at startup (section 3.2.1) */
        /* Put this in a separate function before I get angry */
        {
            AvahiNatpmPrivateInterface *privif;

            for (privif = private_interfaces; privif; privif = privif->ifa_next) {
                /* Has to be allocated because all packets that are sent with
                 * resend are freed at the end of their lives. */
                AvahiNPPacket *pkt = calloc(1, sizeof(*pkt));
                
                if (!pkt) {
                    daemon_log(LOG_ERR, "Out of memory allocating notification packet");
                    goto finish;
                }

                pkt->sock = privif->sock;
                pkt->addr.sin_family = AF_INET;

                if (inet_pton(AF_INET, NATPMP_MCAST_ADDR, &pkt->addr.sin_addr) < 1) {
                    daemon_log(LOG_ERR, "inet_ntop() didn't like %s: %s",
                            NATPMP_MCAST_ADDR, strerror(errno));
                    goto finish;
                }

                pkt->addr.sin_port = htons(NATPMP_PORT);

                prepare_public_ip_notification(pkt);

                daemon_log(LOG_INFO, "%s: Sending gratuitous notification on %s",
                        __FUNCTION__, privif->iface.name);

                send_packet_with_resend(pkt);
            }
        }

        mainloop(pmd_listen_sock);

        /* cleanup */
        if (ipc_req_cleanup(public_interface->name, config.min_port, config.max_port) != 0)
            daemon_log(LOG_WARNING, "Public interface cleanup failed");

        /* This exists because the private interfaces list API is crap */
        {
            AvahiNatpmPrivateInterface *tofree;

            while (private_interfaces) {
                tofree = private_interfaces;
                AVAHI_LLIST_REMOVE(AvahiNatpmPrivateInterface, ifa, private_interfaces, private_interfaces);

                close(tofree->sock);
                tofree->sock = -1;
                avahi_natpm_free_private_interface(tofree);
            }
        }
    }

    ret = 0;

finish:
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);

    if (pmd_listen_sock >= 0)
        close(pmd_listen_sock);

    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 1;
    struct sigaction siga;

    config_filename = avahi_strdup(NATPMD_DEFAULT_CONFIG_FILE);
    if (!config_filename) {
        daemon_log(LOG_ERR, "%s: Out of memory at avahi_strdup",
                __func__);
        goto finish;
    }

    memset(&siga, '\0', sizeof(siga));

    siga.sa_handler = SIG_IGN;

    if (-1 == sigaction(SIGPIPE, &siga, NULL))
        daemon_log(LOG_ERR, "Ignoring SIGPIPE failed");

    if ((argv0 = strrchr(argv[0], '/')))
        argv0 = avahi_strdup(argv0 + 1);
    else
        argv0 = avahi_strdup(argv[0]);

    daemon_pid_file_ident = daemon_log_ident = argv0;

    if (parse_command_line(argc, argv) < 0)
        goto finish;

    if (natpmd_config_load(&config, config_filename) != 0)
        goto finish;

    if (use_syslog)
       daemon_log_use = DAEMON_LOG_SYSLOG;

    if (modify_proc_title)
        avahi_init_proc_title(argc, argv);

    switch (command) {
        case DAEMON_RUN:
            ret = !!go_daemon();
            break;

        case DAEMON_KILL:
            if (daemon_pid_file_kill_wait(SIGTERM, 5) < 0) {
                daemon_log(LOG_WARNING, "Failed to kill daemon: %s", strerror(errno));
                break;
            }

            ret = 0;
            break;

        case DAEMON_VERSION:
            printf("%s " PACKAGE_VERSION "\n", argv0);

            ret = 0;
            break;

        case DAEMON_HELP:
            help(stdout, argv0);
            ret = 0;
            break;

        case DAEMON_CHECK:
            ret = (daemon_pid_file_is_running() >= 0) ? 0 : 1;
            break;
    }

finish:

    if (daemonize)
        daemon_retval_done();

    if (wrote_pid_file)
        daemon_pid_file_remove();

    avahi_free(config_filename);
    natpmd_config_cleanup(&config);
    avahi_free(argv0);

    return ret;
}


/* Adds a packet to the sendqueue (and sends it the first time immediately.
 * returns 0 on success, -1 on error.
 *
 * Error causes (you can probably interrogate errno for these):
 * - Out of memory (ENOMEM)
 */
int send_packet_with_resend(AvahiNPPacket *pkt) {
    AvahiNPQueueItem *qi;
    
    assert(pkt);
    assert(pkt->ever_sent == 0);

    qi = avahi_new(AvahiNPQueueItem, 1);

    if (!qi)
        return -1;

    AVAHI_LLIST_INIT(AvahiNPQueueItem, item, qi);
    qi->next_time = resend_delays[0];
    qi->resends_left = NATPMP_PACKET_RESENDS;
    qi->packet = pkt;

    AVAHI_LLIST_PREPEND(AvahiNPQueueItem, item, resend_queue_head, qi);

    avahi_np_send_and_update(qi);

    update_timer();

    return 0;
}

/**
 * Sends a queue item, updates the queue item.
 * Frees packets and items that are expired (have been sent
 * NATPMP_PACKET_RESENDS times).
 * Also updates (global) queue_head if appropriate.
 * Callers should take the value of item->next before calling this function if
 * they want to iterate through the list.
 * @param item The queue item to send & update
 * @return The next queue item to be processed (possibly NULL).
 */
static void avahi_np_send_and_update(AvahiNPQueueItem *item) {
    assert(item);

    send_packet(item->packet);

    --item->resends_left;

    if (item->resends_left == 0) {
        daemon_log(LOG_DEBUG,
                "Expiring packet queued for %s after %d sends",
                ip4_addr_str(item->packet->addr.sin_addr),
                NATPMP_PACKET_RESENDS);

        AVAHI_LLIST_REMOVE(AvahiNPQueueItem, item, resend_queue_head, item);

        avahi_free(item->packet);
        avahi_free(item);

        return;
    }

    item->next_time = resend_delays[NATPMP_PACKET_RESENDS - item->resends_left];

    update_timer();
}

/**
 * Sends all the packets that are queued for sending.
 * Frees packets and queue items that have expired.
 * Returns 1 if there is still at least one packet in the queue requiring
 * retransmission, or zero if there are no packets in the queue, or -1 if
 * something went wrong.
 */
int process_retransmit_queue(void) {
    AvahiNPQueueItem *item;
    struct timeval now;

    /* This could happen if some other process sends an unexpected SIGALRM. */
    if (!resend_queue_head) {
        daemon_log(LOG_INFO, "%s called with empty queue\n", __FUNCTION__);
        return 0;
    }

    if (gettimeofday(&now, NULL) < 0)
        return -1;

    item = resend_queue_head;
    while (item) {
        if (item->next_time.tv_sec < now.tv_sec ||
                (item->next_time.tv_sec == now.tv_sec && item->next_time.tv_nsec / 1000 <= now.tv_usec)) {
            AvahiNPQueueItem *next = item->item_next;

            avahi_np_send_and_update(item);
            item = next;
        } else {
            daemon_log(LOG_DEBUG, "Skipping packet queued for %s - its retry time has not been reached", ip4_addr_str(item->packet->addr.sin_addr));
            item = item->item_next;
        }
    }

    return 1;
}

/**
 * Determine the soonest packet retransmission time.
 * next_time must not be NULL.
 * This function is slow - it iterates through the full retransmission list.
 * Returns 0 if there are no packets to retransmit, leaving next_time undefined,
 * 1 if there are packets to retransmit, or -1 if some error occurred.
 */
int next_retransmit_time(struct timespec *next_time) {
    int packets_in_list = 0;
    AvahiNPQueueItem *item;

    assert(next_time != NULL);

    for (item = resend_queue_head; item; item = item->item_next) {
        if (packets_in_list == 0 ||
                (item->next_time.tv_sec <= next_time->tv_sec
                 || (item->next_time.tv_sec == next_time->tv_sec &&
                     item->next_time.tv_nsec < next_time->tv_nsec))) {
            next_time->tv_sec = item->next_time.tv_sec;
            next_time->tv_nsec = item->next_time.tv_nsec;
        }
        ++packets_in_list;
    }

    if (packets_in_list) /* Turn it into a timestamp rather than an offset */
        next_time->tv_sec += time(NULL);

    return !!packets_in_list;
}

/* vim:ts=4:sw=4:et:tw=80
 */
