/***
  This file is part of Stallone.
 
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

#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <libdaemon/dlog.h>

#include "timer.h"

/**
 * Also handles an expiry in the past, if you are silly enough to request one.
 * In that case it will trigger immediately.
 *
 * An expiry of (time_t)-1 is ignored.
 */
void timer_notify_expiry(time_t expiry) {
    long int delta;

    if (expiry == -1) {
        daemon_log(LOG_DEBUG, "%s: Ignoring expiry of -1", __FUNCTION__);
        return;
    }
    
    delta = expiry - time(NULL);

    if (delta < 1) {
        daemon_log(LOG_DEBUG, "%s: Firing a SIGALRM right now", __FUNCTION__);
        kill(getpid(), SIGALRM);
    } else {
#if 0 /* noisy */
        daemon_log(LOG_DEBUG, "%s: Set alarm for %ld seconds from now",
                __FUNCTION__, delta);
#endif

        alarm(delta);
    }
}

/* vim: ts=4 sw=4 et tw=80
 */
