#ifndef foonatpmdconfighfoo
#define foonatpmdconfighfoo
/***
  This file is part of Stallone.
  Copyright 2010  Ted Percival <ted@midg3t.net>

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

AVAHI_C_DECL_BEGIN

typedef struct AvahiNatpmdConfig AvahiNatpmdConfig;

struct AvahiNatpmdConfig {
    uint16_t min_port, max_port;
    char *mapping_script;
    char *public_interface_name;
};

int natpmd_config_load(AvahiNatpmdConfig *cfg, const char *filename);
void natpmd_config_cleanup(AvahiNatpmdConfig *cfg);

int natpmd_config_set_mapping_script(AvahiNatpmdConfig *cfg, const char *filename);

AVAHI_C_DECL_END

#endif
/* vim: ts=4 sw=4 et tw=80
 */
