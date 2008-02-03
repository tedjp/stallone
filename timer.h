#ifndef foonatpmtimerhfoo
#define foonatpmtimerhfoo

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

/* A really simple timer mechanism. You keep it notified of the next time you
 * want to be notified, and it sends a SIGALRM as soon as the earliest requested
 * time is reached. At that point you should notify it again of the soonest
 * upcoming timer you want to know about - it only remembers the earliest
 * requested time.
 */

#include <avahi-common/cdecl.h>

AVAHI_C_DECL_BEGIN

void timer_notify_expiry(time_t expiry);

AVAHI_C_DECL_END

#endif

/* vim: ts=4 sw=4 et tw=80
 */
