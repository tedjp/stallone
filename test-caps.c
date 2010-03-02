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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "caps.h"

int main(void) {
#if !defined(HAVE_LIBCAP) || !defined(HAVE_SYS_CAPABILITY_H)
    fprintf(stderr, "No capability support\n");

    return 77;
#else /* LIBCAP support */

    int err;
    cap_t caps;
    cap_flag_value_t capval;

    if (getuid() != 0) {
        fprintf(stderr, "Can only be tested as root\n");
        return 77;
    }

    err = avahi_natpm_drop_caps();
    if (err) {
        fprintf(stderr, "drop_caps failed\n");
        return 1;
    }

    caps = cap_get_proc();
    if (!caps) {
        perror("cap_get_proc failed");
        return 1;
    }

    if (-1 == cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &capval)) {
        perror("cap_get_flag failed");
        return 1;
    }

    if (capval != CAP_CLEAR) {
        fprintf(stderr, "capval was %d, expected CAP_CLEAR(%d)\n",
                capval, CAP_CLEAR);
        return 2;
    }

    cap_free(caps);

    return 0;
#endif /* LIBCAP support */
}

/* vim: ts=4 sw=4 et tw=80
 */
