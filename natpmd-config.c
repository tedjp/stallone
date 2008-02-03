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

#include <stdlib.h>
#include <string.h>

#include <libdaemon/dlog.h>
#include <avahi-common/malloc.h>
#include <avahi-common/ini-file-parser.h>

#include "natpmd-config.h"

#define NATPMD_CONFIG_SECTION "natpmd"

static int apply_config(AvahiNatpmdConfig *cfg, const char *filename);

/**
 * Fill in the config structure based on defaults and the contents of the
 * named configuration file.
 *
 * @return 0 on success, -1 on error.
 */
int natpmd_config_load(AvahiNatpmdConfig *cfg, const char *filename) {

    assert(cfg);
    assert(filename);

    /* Default config options */
    {
        cfg->min_port = NATPMD_DEFAULT_MIN_PORT;
        cfg->max_port = NATPMD_DEFAULT_MAX_PORT;

        cfg->mapping_script = avahi_strdup(NATPMD_DEFAULT_MAPPING_SCRIPT);
        if (!cfg->mapping_script) {
            daemon_log(LOG_ERR, "%s: Out of memory", __func__);
            return -1;
        }
    }

    return apply_config(cfg, filename);
}

/**
 * Sets the action script.
 *
 * Returns 0 on success or -1 if there was a problem.
 * On error, the config's mapping script is undefined.
 */
int natpmd_config_set_mapping_script(AvahiNatpmdConfig *cfg, const char *filename) {

    assert(cfg);
    assert(filename);

    if (filename[0] != '/') {
        /* TODO: Implement something like canonicalize_file_name() except don't
         * resolve symlinks. Put it in avahi-common and add it to this and
         * avahi-autoipd.
         */
        daemon_log(LOG_ERR,
                "%s: Action script \"%s\" must be an absolute pathname",
                __func__, filename);
        return -1;
    }

    avahi_free(cfg->mapping_script);

    cfg->mapping_script = avahi_strdup(filename);
    if (!cfg->mapping_script) {
        daemon_log(LOG_ERR, "%s: Out of memory, failing", __func__);
        return -1;
    }

    return 0;
}

/**
 * Frees any memory associated with a given config structure.
 */
void natpmd_config_cleanup(AvahiNatpmdConfig *cfg) {

    assert(cfg);

    avahi_free(cfg->mapping_script);
    cfg->mapping_script = NULL;
}

/**
 * Set the given port to that specified in the string.
 *
 * @return 0 if the port was valid, -1 if it was invalid.
 */
static int parse_port(uint16_t *port, const char *str) {
    long lport;
    char *endptr;

    lport = strtol(str, &endptr, 0);

    if (*endptr || lport < 1 || lport > UINT16_MAX) {
        daemon_log(LOG_ERR,
                "%s: Invalid port \"%s\"",
                __func__, str);
        return -1;
    }

    /* Valid port */
    *port = lport;
    return 0;
}

/**
 * Read the configuration and apply it.
 * Returns 0 if the config was OK and parsed correctly, or
 * -1 if there was a fatal problem with the config.
 */
static int apply_config(AvahiNatpmdConfig *cfg, const char *filename) {
    int ret = -1; /*< return code */
    AvahiIniFile *file = NULL;
    const AvahiIniFileGroup *group;
    const AvahiIniFilePair *pair;

    file = avahi_ini_file_load(filename);
    if (!file)
        goto cleanup;

    /* Walk the config parsing [natpmd] sections (there may be several) */
    for (group = file->groups; group; group = group->groups_next) {
        if (strcmp(group->name, NATPMD_CONFIG_SECTION) == 0) {
            for (pair = group->pairs; pair; pair = pair->pairs_next) {

                assert(pair->key);
                assert(pair->value);

                if        (strcmp(pair->key, "min-port") == 0) {
                    parse_port(&cfg->min_port, pair->value);
                } else if (strcmp(pair->key, "max-port") == 0) {
                    parse_port(&cfg->max_port, pair->value);
                } else if (strcmp(pair->key, "mapping-script") == 0) {
                    natpmd_config_set_mapping_script(cfg, pair->value);
                } else {
                    daemon_log(LOG_WARNING,
                            "%s: Ignoring unknown configuration option \"%s\"",
                            __func__, pair->key);
                }
            } /* natpmd group */
        } else {
            daemon_log(LOG_DEBUG, "%s: Ignoring section [%s]",
                    __func__, group->name);
        }
    } /* groups */

    if (cfg->min_port > cfg->max_port) {
        uint16_t tmp_port;
        daemon_log(LOG_WARNING,
                "%s: min-port %hu is higher than max-port %hu, "
                "will assume they should be the other way around",
                __func__, cfg->min_port, cfg->max_port);
        tmp_port = cfg->min_port;
        cfg->min_port = cfg->max_port;
        cfg->max_port = tmp_port;
    }

    ret = 0; /* success */

cleanup:
    if (file)
        avahi_ini_file_free(file);

    return ret;
}

/* vim: ts=4 sw=4 et tw=80
 */
