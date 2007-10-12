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
# include <config.h>
#endif

#include <errno.h>
#include <string.h>

#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libdaemon/dlog.h>


int avahi_natpm_drop_caps(void) {
    int ret = 0;
#if defined(HAVE_SYS_CAPABILITY_H) && defined(HAVE_LIBCAP)
    cap_t caps;
#if LIBCAP_MADE_THE_POINTER_CONST_LIKE_IT_SHOULD_HAVE_BEEN
    const /* continues... */
#endif
    cap_value_t inherit_caps[] = { CAP_NET_ADMIN };
    /* Not setting any effective or permitted flags, meaning this process
     * wants to be totally incapable (except for its inheritable set) */

    caps = cap_init();
    if (!caps)
        return -1;

    if (-1 == cap_set_flag(caps, CAP_INHERITABLE,
            sizeof(inherit_caps) / sizeof(inherit_caps[0]),
            inherit_caps, CAP_SET))
    {
        daemon_log(LOG_WARNING,
                "%s: Unable to assign inheritable capabilities: %s",
                __func__, strerror(errno));
        ret = -1;
        goto cleanup;
    }

    if (-1 == cap_set_proc(caps)) {
        daemon_log(LOG_ERR, "%s: Unable to set reduced capability set: %s",
                __func__, strerror(errno));
        ret = -1;
        goto cleanup;
    }

cleanup:
    cap_free(caps);
#endif /* libcap */
    return ret;
}

/* vim: ts=4 sw=4 et tw=80
 */
