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
# include <config.h>
#endif

#include <unistd.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <libdaemon/dlog.h>
#include <avahi-common/fdutil.h>
#include <avahi-common/setproctitle.h>

#include "caps.h"
#include "common.h"
#include "ipc.h"
#include "worker.h"


/* XXX: Should this be based on IPC_WAIT_TIME in natpmd.c?
 *      It is currently one second less than that. */
#define MAX_RUN_SECONDS 3 

/* XXX: Not sure if this works properly with signals.
 */

extern char *argv0;
static const char *mapping_script;

/*
 * This is pretty simple. It sits on a blocking read of the socket, and when
 * it receives a request it executes the helper script and waits for it to
 * finish before returning a result.
 * This means it only requests and processes a single request at a time.
 * It might choose to set a signal (SIGALRM) to wake it up after some time
 * (5 seconds?) to indicate that the request took too long, and return
 * failure.
 *
 * Success or failure is reported to the main/parent natpmd process by sending
 * an AvahiPmIpcResponse.
 */

static int op_add_remove(const AvahiNatpmdIPCReq *req);
static int op_clear(const AvahiNatpmdIPCReq *req);
static int op_prepare_cleanup(const AvahiNatpmdIPCReq *req);
static void sigchld_handler(int sig);

/**
 * Return value is the process return value - zero on success or 1 on failure.
 * 
 * FIXME: This function is too long and unclear whether some code paths return
 * an IPC packet (or whether they shouldn't). There are probably lots of latent
 * bugs.
 */
int worker(const char *mapping_script_file, int sock) {
    ssize_t siz;
    AvahiNatpmdIPCReq req;

    assert(mapping_script_file);
    assert(mapping_script_file[0] == '/');

    mapping_script = mapping_script_file;

    if (avahi_natpm_drop_caps() != 0)
        return 1;

    avahi_set_cloexec(sock);
    /* XXX: Audit to ensure no extra sockets are passed to the child */

    avahi_set_proc_title(argv0, "%s: iptables helper", argv0);

    daemon_log(LOG_DEBUG, "%s: Worker process running with pid %d",
            __FUNCTION__, getpid());

    while ((siz = recv(sock, &req, sizeof(req), 0)) > 0) {
        pid_t pid;
        int status;
        sigset_t newsigs, oldsigs;

        if (siz != sizeof(req)) {
            daemon_log(LOG_NOTICE, "IPC request packet was too short");
            continue;
        }

        /* Prevent a race where the signal gets delivered before we wait on it
         */
        if (-1 == sigemptyset(&newsigs)) {
            daemon_log(LOG_ERR, "sigemptyset() failed: %s", strerror(errno));
            return 1;
        }

        if (-1 == sigaddset(&newsigs, SIGCHLD)) {
            daemon_log(LOG_ERR, "sigaddset(..., SIGCHLD) failed: %s", strerror(errno));
            return 1;
        }

        if (-1 == sigprocmask(SIG_BLOCK, &newsigs, &oldsigs)) {
            daemon_log(LOG_ERR, "sigprocmask(SIG_BLOCK, ...) failed: %s", strerror(errno));
            return 1;
        }

        pid = fork();
        
        if (pid == -1) {
            daemon_log(LOG_ERR, "%s: fork() failed: %s", __FUNCTION__, strerror(errno));
            return 1;
        }

        if (pid == 0) {
            /* child */
            int ret = 1; /* Child process' return value */

            /* Let the child receive SIGCHLD if it wants to */
            if (-1 == sigprocmask(SIG_UNBLOCK, &newsigs, NULL))
                daemon_log(LOG_WARNING, "Child worker process failed to unblock signals: %s",
                        strerror(errno));

            switch(req.op) {
                case IPCREQ_OP_ADD: /*@fallthrough@*/
                case IPCREQ_OP_REMOVE:
                    ret = op_add_remove(&req);
                    break;

                case IPCREQ_OP_PREPARE: /*@fallthrough@*/
                case IPCREQ_OP_CLEANUP:
                    ret = op_prepare_cleanup(&req);
                    break;

                case IPCREQ_OP_CLEAR:
                    ret = op_clear(&req);
                    break;

                default:
                    daemon_log(LOG_WARNING, "Received an IPC packet with bogus operation field");
                    ret = 1;
            }
            
            _exit(ret); /* The child process ends here. */
        }

        { /* parent */
            int signum;
            siginfo_t siginfo;
            const struct timespec waittime = { MAX_RUN_SECONDS, 0 };
            struct sigaction oldhandler, ourhandler;
            pid_t waitedpid;

            memset(&ourhandler, '\0', sizeof(ourhandler));

            ourhandler.sa_handler = sigchld_handler;

            /* Set signal handler for SIGCHLD */
            if (-1 == sigaction(SIGCHLD, &ourhandler, &oldhandler)) {
                daemon_log(LOG_ERR, "Setting signal handler for SIGCHLD failed: %s",
                        strerror(errno));
                return 1;
            }

            /* XXX: Check for SIGHUP and SIGTERM too to stay interactive? */
            while ((signum = sigtimedwait(&newsigs, &siginfo, &waittime)) == -1 && errno == EINTR)
                ;

            assert(signum == SIGCHLD || (signum == -1 && errno == EAGAIN));

            /* Remove signal handler for SIGCHLD */
            if (-1 == sigaction(SIGCHLD, &oldhandler, NULL)) {
                daemon_log(LOG_ERR, "Restoring old SIGCHLD handler failed: %s",
                        strerror(errno));
                return 1;
            }

            /* Restore old signal state */
            if (-1 == sigprocmask(SIG_SETMASK, &oldsigs, NULL)) {
                /* Only fails if SIG_SETMASK is invalid. Never happens ;) */
                daemon_log(LOG_WARNING, "Restoring signal state (sigprocmask(SIG_SETMASK, ...)) failed: %s",
                        strerror(errno));
            }

            if (signum == -1) {
                assert(errno == EAGAIN);
                /* errno could also be EINVAL if waittime is invalid, in which
                 * case we're stuffed anyway */

                daemon_log(LOG_ERR, "Child worker process took more than %ld seconds, gave up waiting",
                        waittime.tv_sec);
                continue;
            }

            /* SIGCHLD arrived. */

            while (((waitedpid = waitpid(pid, &status, WNOHANG)) == -1 && errno == EINTR) || waitedpid != pid)
                ;

            if (waitedpid == -1) {
                daemon_log(LOG_ERR, "%s: Error waiting for child process to finish: %s",
                        __FUNCTION__, strerror(errno));
                continue;
            }

            assert(waitedpid == pid);

            if (pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                req.result = NATPMP_RESULT_SUCCESS;
            } else {
                if (pid == -1) {
                    daemon_log(LOG_WARNING, "%s: waitpid failed: %s (probably timed out)",
                            __FUNCTION__, strerror(errno));
                } else {
                    if (WIFEXITED(status))
                        daemon_log(LOG_ERR, "%s: Child exited with status %d",
                                __FUNCTION__, WEXITSTATUS(status));
                    else if (WIFSIGNALED(status))
                        daemon_log(LOG_ERR, "%s: Child exited due to signal %d",
                                __FUNCTION__, WTERMSIG(status));
                    else
                        daemon_log(LOG_ERR, "%s: Child exited, unknown cause",
                                __FUNCTION__);
                }
                req.result = NATPMP_RESULT_NO_RESOURCES;
            }

            if (send(sock, &req, sizeof(req), 0) < (ssize_t)sizeof(req))
                daemon_log(LOG_WARNING, "Failed sending IPC response");
        }
    }

    if (siz == -1) { /* FIXME: EINTR / EAGAIN? */
        daemon_log(LOG_ERR, "%s: Error receiving on IPC socket", __FUNCTION__);
        return 1;
    }
    else {
        assert(siz == 0);
        daemon_log(LOG_INFO, "%s: IPC socket closed, exiting.", __FUNCTION__);
    }

    return 0;
}

/**
 * Returns 0 on success or 1 on failure.
 * The return value is intended to be used as the child process' return value.
 */
int op_add_remove(const AvahiNatpmdIPCReq *req) {
    char str_priv[6], str_pub[6];
    struct in_addr saddr;

    assert(req);
    assert(mapping_script);

    daemon_log(LOG_DEBUG, "%s: req->op = %d, req->proto = %d",
            __FUNCTION__, req->op, req->proto);

    assert(req->op == IPCREQ_OP_ADD || req->op == IPCREQ_OP_REMOVE);
    assert(req->proto == IPCREQ_PROTO_TCP || req->proto == IPCREQ_PROTO_UDP);

    saddr.s_addr = req->dest_addr;

    if (snprintf(str_priv, sizeof(str_priv), "%hu", req->dest_port) >= (ssize_t)sizeof(str_priv))
        return 1;

    if (snprintf(str_pub, sizeof(str_pub), "%hu", req->pub_port) >= (ssize_t)sizeof(str_pub))
        return 1;

    daemon_log(LOG_DEBUG, "%s: Executing %s %s %s %s %s %s",
            __FUNCTION__,
            mapping_script,
            req->op == IPCREQ_OP_ADD ? "ADD" : "REMOVE",
            req->proto == IPCREQ_PROTO_TCP ? "TCP" : "UDP",
            str_pub,
            ip4_addr_str(saddr),
            str_priv);

    /* XXX: Use daemon_exec()? */
    execl(  mapping_script,
            mapping_script,
            req->op == IPCREQ_OP_ADD ? "ADD" : "REMOVE",
            req->proto == IPCREQ_PROTO_TCP ? "TCP" : "UDP",
            str_pub,
            ip4_addr_str(saddr),
            str_priv,
            NULL);

    daemon_log(LOG_ERR, "%s: execl() failed: %s", __FUNCTION__, strerror(errno));

    return 1;
}

int op_prepare_cleanup(const AvahiNatpmdIPCReq *req) {
    char smin_port[6], smax_port[6];
    const char *op;

    assert(req);
    assert(mapping_script);

    if (req->op == IPCREQ_OP_PREPARE)
        op = "PREPARE";
    else if (req->op == IPCREQ_OP_CLEANUP)
        op = "CLEANUP";
    else
        assert(0);

    if (snprintf(smin_port, sizeof(smin_port), "%hu", req->min_port) >= (ssize_t)sizeof(smin_port))
        return 1;

    if (snprintf(smax_port, sizeof(smax_port), "%hu", req->max_port) >= (ssize_t)sizeof(smax_port))
        return 1;

    daemon_log(LOG_DEBUG, "%s: Executing %s %s %s %s %s",
            __FUNCTION__,
            mapping_script,
            op,
            req->interface,
            smin_port,
            smax_port);

    execl(  mapping_script,
            mapping_script,
            op,
            req->interface,
            smin_port,
            smax_port,
            NULL);

    daemon_log(LOG_ERR, "%s: execl() failed: %s", __FUNCTION__, strerror(errno));

    return 1;
}

int op_clear(const AvahiNatpmdIPCReq *req) {
    assert(req);
    assert(mapping_script);

    daemon_log(LOG_DEBUG, "%s", __FUNCTION__);

    /* XXX: Use daemon_exec()? */
    execl(  mapping_script,
            mapping_script,
            "CLEAR",
            NULL);

    daemon_log(LOG_ERR, "%s: execl() failed: %s", __FUNCTION__, strerror(errno));

    return 1;
}

/**
 * This is not even called, but has to be registered or SIGCHLD is never
 * delivered. There is a small chance that it could be called if an extra
 * SIGCHLD arrives, though.
 */
static void sigchld_handler(int sig) {
    
    assert(sig == SIGCHLD);

    daemon_log(LOG_DEBUG, "%s: SIGCHLD!", __FUNCTION__);
}


/* vim: ts=4 sw=4 et tw=80
 */
