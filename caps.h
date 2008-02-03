#ifndef foonatpmpcapshfoo
#define foonatpmpcapshfoo

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

#if defined(HAVE_SYS_CAPABILITY_H)
# include <sys/capability.h>
#endif

#include <avahi-common/gccmacro.h>

AVAHI_C_DECL_BEGIN

int avahi_natpm_drop_caps(void);

AVAHI_C_DECL_END

#endif
/* vim: ts=4 sw=4 et tw=80
 */
