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

#undef memcmp

#include <stddef.h>

int memcmp();

int rpl_memcmp(const void *s1, const void *s2, size_t n) {
    size_t i;
    const char *c1 = s1, *c2 = s2;

    for (i = 0; i < n; ++i) {
        if (c1[i] != c2[i]) {
            return c2[i] - c1[i];
        }
    }

    return 0;
}
