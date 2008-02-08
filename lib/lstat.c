/***
  This file is part of Stallone.
  Copyright 2008  Ted Percival <ted@midg3t.net>

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

#undef lstat

#include <sys/stat.h>
#include <errno.h>

int lstat();

/* FIXME: This should also ensure trailing slashes are honoured, a la
 * AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK */
int rpl_lstat(const char *path, struct stat *buf) {
    if (*path == '\0') {
        errno = ENOENT;
        return -1;
    }

    return lstat(path, buf);
}
