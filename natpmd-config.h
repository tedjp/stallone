#ifndef foonatpmdconfighfoo
#define foonatpmdconfighfoo
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

#include <stdint.h>

#include <avahi-common/cdecl.h>

#define DEFAULT_MIN_PORT 30800
#define DEFAULT_MAX_PORT 30999
#define NATPMD_CONFIG_SECTION "natpmd"

AVAHI_C_DECL_BEGIN

typedef struct AvahiNatpmdConfig AvahiNatpmdConfig;

struct AvahiNatpmdConfig {
    uint16_t min_port, max_port;
    char *action_script;
};

int natpmd_config_load(AvahiNatpmdConfig *cfg, const char *filename);
void natpmd_config_cleanup(AvahiNatpmdConfig *cfg);

void natpmd_config_set_action_script(AvahiNatpmdConfig *cfg, const char *filename);

AVAHI_C_DECL_END

#endif
/* vim: ts=4 sw=4 et tw=80
 */
