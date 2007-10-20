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

#define _SVID_SOURCE /* for tempnam */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include <avahi-common/gccmacro.h>

#include "natpmd-config.h"

/* TODO: Use the TMPDIR environment variable if it is set */
#define TMPFILETEMPLATE "/tmp/natpmd-test-XXXXXX"

/* Same as in natpmd-config.c */
#define NATPMD_CONFIG_SECTION "natpmd"

static char tmpfilename[] = TMPFILETEMPLATE;
static int remove_tempfile = 0;

static void skip(const char *reason, ...) {
    va_list ap;
    va_start(ap, reason);
    vfprintf(stderr, reason, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(77);
}

/* Called automatically on exit */
static void cleanup(void) {
    if (remove_tempfile) {
        if (unlink(tmpfilename) == -1) {
            fprintf(stderr, "removing temp file %s failed: %s",
                    tmpfilename, strerror(errno));
        }
    }
}

/**
 * Write the given contents to the test file (tmpfilename).
 * Returns -1 if there was a problem, 0 on success.
 */
static int write_testfile(const char *format, ...) AVAHI_GCC_PRINTF_ATTR12;
static int write_testfile(const char *format, ...) {
    int ok = 0;
    FILE *testfile;
    va_list ap;

    testfile = fopen(tmpfilename, "w");
    if (!testfile) {
        fprintf(stderr,
                "fopen tmpfile %s failed: %s", tmpfilename, strerror(errno));
    } else {
        /* Testfile written OK */
        va_start(ap, format);
        if (vfprintf(testfile, format, ap) < 0) {
            fprintf(stderr, "vfprintf to tmpfile %s failed: %s",
                    tmpfilename, strerror(errno));
        } else {
            ok = 1;
        }
        va_end(ap);

        if (fclose(testfile) == -1) {
            fprintf(stderr, "Problem closing test file: %s", strerror(errno));
            /* file contents probably truncated -- will cause a failure */
            ok = 0;
        }
    }
    return ok ? 0 : -1;
}

int main(void) {
    int failures = 0;
    AvahiNatpmdConfig config;
    int fd;

    memset(&config, '\0', sizeof(config));

    if (atexit(&cleanup) != 0) {
        fprintf(stderr,
                "Failed to register cleanup function, continuing anyway.\n");
    }

    fd = mkstemp(tmpfilename);
    if (fd == -1)
        skip("mkstemp failed to create temp file: %s", strerror(errno));

    remove_tempfile = 1;

    /* Close the file and reopen it with stdio for easier IO */
    if (close(fd) == -1) {
        fprintf(stderr,
                "close tmpfile %s failed: %s, continuing anyway",
                tmpfilename, strerror(errno));
    }
    fd = -1;

#define TEST_MIN_PORT 123
#define TEST_MAX_PORT 456
#define TEST_MAPPING_SCRIPT "/some-mapping-script"

    if (write_testfile(
            "[%s]\n"
            "min-port=%d\n"
            "max-port=%d\n"
            "mapping-script=%s\n"
            "unexpected-option=foo\n"
            "[unrecognised-section]\n"
            "something=something-else\n",
            NATPMD_CONFIG_SECTION, TEST_MIN_PORT, TEST_MAX_PORT,
            TEST_MAPPING_SCRIPT) == -1)
        skip("Cannot write testfile");

    /* Now for the testing */
    if (natpmd_config_load(&config, tmpfilename) != 0) {
        fprintf(stderr, "Failed to load config.\n");
        ++failures;
    } else {
        /* Successfully loaded the config */
        if (config.min_port != TEST_MIN_PORT) {
            fprintf(stderr, "Wrong min port, got %hu but expected %d\n",
                    config.min_port, TEST_MIN_PORT);
            ++failures;
        }
        if (config.max_port != TEST_MAX_PORT) {
            fprintf(stderr, "Wrong max port, got %hu but expected %d\n",
                    config.max_port, TEST_MAX_PORT);
            ++failures;
        }
        if (!config.mapping_script) {
            fprintf(stderr, "Mapping script was NULL\n");
            ++failures;
        } else if (strcmp(config.mapping_script, TEST_MAPPING_SCRIPT) != 0) {
            fprintf(stderr, "Unexpected result for mapping script; got [%s] "
                    "but expected [%s]\n",
                    config.mapping_script, TEST_MAPPING_SCRIPT);
            ++failures;
        }

        natpmd_config_cleanup(&config);
    }

    /* Ensure parsing a nonexistent file fails */
#define NONEXIST_FILENAME "/nonexistent-file"
    if (natpmd_config_load(&config, NONEXIST_FILENAME) != -1) {
        /* I don't believe it. Ensure the file really doesn't exist */
        struct stat sbuf;
        if (stat(NONEXIST_FILENAME, &sbuf) == -1 && errno == ENOENT) {
            fprintf(stderr, "Successfully loaded config from a non-existent "
                    "file. WTF?\n");
            ++failures;
        }
    }

    /* Test invalid port string */
    if (write_testfile(
            "[%s]\n"
            "min-port=0\n",
            NATPMD_CONFIG_SECTION) == -1)
        skip("Problem writing testfile");

    if (natpmd_config_load(&config, tmpfilename) == 0 &&
            config.min_port < 1) {
        fprintf(stderr, "Received invalid port number zero\n");
        ++failures;
    }

    /* Test inverted min/max values */
    if (write_testfile(
                "[%s]\n"
                "min-port=2345\n"
                "max-port=1234\n",
                NATPMD_CONFIG_SECTION) == -1)
        skip("Problem writing testfile");

    natpmd_config_load(&config, tmpfilename);
    if (config.min_port > config.max_port) {
        fprintf(stderr, "min-port %hu is greater than max-port %hu\n",
                config.min_port, config.max_port);
        ++failures;
    }

    return !!failures;
}

/* vim: ts=4 sw=4 et tw=80
 */
