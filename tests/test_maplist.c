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
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <time.h>

#include "../maplist.h"

static int test_noinit(void);
static int test_init(void);
static int test_add_remove_count(void);
static int test_find(void);
static int test_find_hosts(void);
static int test_find_single_host(void);
static int test_expiry(void);

int main(void) {
    int failures = 0;

    failures += test_noinit();
    failures += test_init();
    failures += test_add_remove_count();
    failures += test_find();
    failures += test_find_hosts();
    failures += test_find_single_host();
    failures += test_expiry();

    return !!failures;
}

#define TEST_EXPECT_PTR(t, e) \
    do { \
        void *_testret; \
        _testret = (t); \
        if (_testret != (e)) { \
            fprintf(stderr, "%s:%d %s returned %p instead of %p\n", \
                    __FUNCTION__, __LINE__, #t, _testret, (e)); \
            ++failures; \
        } \
    } while(0)

#define TEST_EXPECT_INT(t, e) \
    do { \
        int _testret; \
        _testret = (t); \
        if (_testret != (e)) { \
            fprintf(stderr, "%s:%d %s returned %d instead of %d\n", \
                    __FUNCTION__, __LINE__, #t, _testret, (e)); \
            ++failures; \
        } \
    } while(0)

/* Tries to initialise something. If it can't be initialised, an error is
 * printed and the current value of 'failures' is returned.
 */
#define REQUIRE_INIT(t, e) \
    do { \
        int _testret; \
        _testret = (t); \
        if (_testret != (e)) { \
            fprintf(stderr, "%s:%d Initialisation %s failed (returned %d, expected %d), skipping.\n", \
                    __FUNCTION__, __LINE__, #t, _testret, (e)); \
            return failures; \
        } \
    } while(0)

#if 0
#define TEST_EXPECT_RETURN(t, e, r) ...
#endif

/**
 * Test to ensure functions that require init() return a failure code if they
 * are called when mapping has not been initialised (or has been finalised with
 * *_cleanup()).
 *
 * Returns the number of functions that failed.
 */
int test_noinit(void) {
    int failures = 0;
    int round;
    AvahiNatpmMap bogusmap;
    AvahiNatpmMap **results; /* Array of pointers */

    /* Round 1 is done before initialising anything.
     * Round 2 is done after initialising and cleanup (which should be
     * effectively the same as round 1). */
    for (round = 1; round <= 2; ++round) {
        memset(&bogusmap, '\0', sizeof(bogusmap));

        if (round == 2) {
            TEST_EXPECT_INT(avahi_natpm_maplist_init(), 0);
            avahi_natpm_maplist_cleanup();
        }

        TEST_EXPECT_INT(avahi_natpm_maplist_count(), -1);

        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)-1);

        results = NULL;
        TEST_EXPECT_INT(avahi_natpm_maplist_find_expired(&results), -1);
        TEST_EXPECT_PTR(results, NULL);

        results = NULL;
        TEST_EXPECT_INT(avahi_natpm_maplist_find_byhost(0, &results), -1);
        TEST_EXPECT_PTR(results, NULL);

        TEST_EXPECT_INT(avahi_natpm_maplist_add(&bogusmap), -1);

        /* The functions that don't return anything need to be called for
         * full coverage. */
        avahi_natpm_maplist_cleanup();
        avahi_natpm_maplist_remove(&bogusmap);
        avahi_natpm_maplist_remove_all();
    }

    return failures;
}

/**
 * Test to see whether init and cleanup work.
 */
int test_init(void) {
    int failures = 0;

    TEST_EXPECT_INT(avahi_natpm_maplist_init(), 0);
    /* Init should only succeed once */
    TEST_EXPECT_INT(avahi_natpm_maplist_init(), -1);
    avahi_natpm_maplist_cleanup();

    return failures;
}

#define OOM() do { \
    fprintf(stderr, "Skipping test due to low memory\n"); \
    exit(77); \
} while (0)

static AvahiNatpmMap *make_map(AvahiNPProto proto, time_t expiry_offset) {
    AvahiNatpmMap *map;
    struct per_proto *p;

    map = avahi_natpm_map_create();

    if (!map)
        OOM();

    if (proto == NATPMP_PROTO_TCP)
        p = &map->tcp;
    else
        p = &map->udp;

    p->expiry = expiry_offset + time(NULL);
    p->state = PORT_MAPPED;

    return map;
}

int test_add_remove_count(void) {
    int failures = 0;
    const int total_count = 6; /* how many to add & remove */
    AvahiNatpmMap *testmaps[total_count];
    int i = 0;

    REQUIRE_INIT(avahi_natpm_maplist_init(), 0);

    testmaps[0] = make_map(NATPMP_PROTO_TCP, 86400);

    /* Basic tests using one */
    TEST_EXPECT_INT(avahi_natpm_maplist_count(), 0);
    TEST_EXPECT_INT(avahi_natpm_maplist_add(testmaps[0]), 0);
    TEST_EXPECT_INT(avahi_natpm_maplist_count(), 1);
    TEST_EXPECT_INT(avahi_natpm_maplist_remove(testmaps[0]), 0);
    TEST_EXPECT_INT(avahi_natpm_maplist_count(), 0);

    /* Add a bunch */
    for (i = 0; i < total_count; ++i) {
        testmaps[i] = make_map(NATPMP_PROTO_TCP, 86400);

        TEST_EXPECT_INT(avahi_natpm_maplist_add(testmaps[i]), 0);
    }

    TEST_EXPECT_INT(avahi_natpm_maplist_count(), i);

    /* Remove a bunch */
    for (i = total_count - 1; i >= 0; --i)
        TEST_EXPECT_INT(avahi_natpm_maplist_remove(testmaps[i]), 0);

    TEST_EXPECT_INT(avahi_natpm_maplist_count(), 0);

    /* Test the remove_all func */
    memset(testmaps, '\0', sizeof(*testmaps) * total_count);

    for (i = 0; i < total_count; ++i)
        avahi_natpm_maplist_add(make_map(NATPMP_PROTO_TCP, 86400));

    avahi_natpm_maplist_remove_all();
    TEST_EXPECT_INT(avahi_natpm_maplist_count(), 0);

    /* Test the cleanup func */
    memset(testmaps, '\0', sizeof(*testmaps) * total_count);

    for (i = 0; i < total_count; ++i)
        avahi_natpm_maplist_add(make_map(NATPMP_PROTO_TCP, 86400));

    avahi_natpm_maplist_cleanup();
    TEST_EXPECT_INT(avahi_natpm_maplist_count(), -1);

    return failures;
}

/**
 * Tests the *_find_expired() function and some characteristics of the
 * function that are assumed to be shared by all the other find_* functions.
 *
 * TODO: Ensure no code paths are untested because this only uses tcp expiry at
 * the moment.
 */
int test_find(void) {
    int failures = 0;
    const int total_count = 3;
    AvahiNatpmMap *testmaps[total_count];
    AvahiNatpmMap **results;
    AvahiNatpmMap *pcanary = NULL;
    int i, numres;
    const time_t now = time(NULL);

    REQUIRE_INIT(avahi_natpm_maplist_init(), 0);

    /* Test the no-match case */
    for (i = 0; i < total_count; ++i) {
        testmaps[i] = make_map(NATPMP_PROTO_TCP, 86400);
        REQUIRE_INIT(avahi_natpm_maplist_add(testmaps[i]), 0);
    }

    results = &pcanary;
    numres = avahi_natpm_maplist_find_expired(&results);
    
    TEST_EXPECT_INT(numres, 0);

    if (results != NULL) {
        ++failures;

        fprintf(stderr, "%s:%d results was not set properly\n",
                __FUNCTION__, __LINE__);

        if (results == &pcanary)
            fprintf(stderr, "%s:%d it was still set to the canary value\n",
                    __FUNCTION__, __LINE__);
    }

    avahi_natpm_maplist_remove_all();

    /* Test for some matches */
    for (i = 0; i < total_count; ++i) {
        if ((testmaps[i] = avahi_natpm_map_create()) == NULL)
            OOM();
    }

    testmaps[0]->tcp.expiry = now - 86400; /* expired */
    testmaps[0]->tcp.state = PORT_MAPPED;

    testmaps[1]->tcp.expiry = now + 86400;
    testmaps[1]->tcp.state = PORT_MAPPED;

    testmaps[2]->udp.expiry = now - 86400; /* expired */
    testmaps[2]->udp.state = PORT_MAPPED;

    for (i = 0; i < total_count; ++i)
        REQUIRE_INIT(avahi_natpm_maplist_add(testmaps[i]), 0);

    numres = avahi_natpm_maplist_find_expired(&results);
    if (numres != 2) {
        fprintf(stderr, "%s:%d Unexpected number of results: %d, expected 2\n",
                __FUNCTION__, __LINE__, numres);
        return 1;
    }
    if (results == NULL) {
        fprintf(stderr, "%s:%d Results pointer is NULL\n",
                __FUNCTION__, __LINE__);
        return 1;
    }

    /* Don't assume anything about ordering of results */
    for (i = 0; i < 2; ++i) {
        const AvahiNatpmMap *cur = results[i];
        if (cur != testmaps[0] && cur != testmaps[2]) {
            fprintf(stderr, "%s:%d Unexpected result: i=%d, cur=%p\n",
                    __FUNCTION__, __LINE__, i, (const void*)cur);
            ++failures;
        }
    }

    avahi_natpm_maplist_free_result(results);
    results = NULL;

    avahi_natpm_maplist_cleanup();

    return failures;
}

/**
 * Tests finding of hosts and removal of particular entries.
 */
int test_find_hosts(void) {
    int failures = 0;
    AvahiNatpmMap *maps[3], *canary = NULL, **results = &canary;
    int host_to_remove;
    int numres;

    REQUIRE_INIT(avahi_natpm_maplist_init(), 0);

    numres = avahi_natpm_maplist_find_byhost((in_addr_t) 1, &results);
    TEST_EXPECT_INT(numres, 0);
    if (results != NULL) {
        ++failures;

        fprintf(stderr, "%s:%d results PTR was not NULL",
                __FUNCTION__, __LINE__);
        if (results == &canary)
            fprintf(stderr, "%s:%d results PTR was still set to canary",
                    __FUNCTION__, __LINE__);
    }

    for (host_to_remove = 1; host_to_remove <= 3; ++host_to_remove) {
        int i;

        for (i = 0; i < 3; ++i) {
            maps[i] = make_map(NATPMP_PROTO_TCP, 123);
            maps[i]->private_addr = i + 1;

            REQUIRE_INIT(avahi_natpm_maplist_add(maps[i]), 0);
        }

        numres = avahi_natpm_maplist_find_byhost(host_to_remove, &results);
        TEST_EXPECT_INT(numres, 1);
        TEST_EXPECT_PTR(results[0], (void*)maps[host_to_remove-1]);

        /* Free memory */
        avahi_natpm_maplist_free_result(results);
        avahi_natpm_maplist_remove_all();

    }

    avahi_natpm_maplist_cleanup();

    return failures;
}

int test_find_single_host(void) {
    int failures = 0;
    int round;
    const uint16_t port = 8080;
    const in_addr_t host = 0x0a000000;
    AvahiNPProto proto = NATPMP_MAP_TCP;
    AvahiNatpmMap *result, *map;

    REQUIRE_INIT(avahi_natpm_maplist_init(), 0);

    TEST_EXPECT_PTR(avahi_natpm_maplist_find_hostportproto(host, port, proto), NULL);

    /* Test the no-match case */
    map = make_map(NATPMP_PROTO_UDP, 86400);

    map->private_addr = host;
    map->tcp.private_port = port;

    REQUIRE_INIT(avahi_natpm_maplist_add(map), 0);
    
    result = avahi_natpm_maplist_find_hostportproto(host, port, NATPMP_PROTO_TCP);
    TEST_EXPECT_PTR(result, NULL);

    avahi_natpm_maplist_remove_all();

    for (round = 0; round < 3; ++round) {
        /* Round 0: matching host, non-matching port.
         * Round 1: non-matching host, matching port.
         * Round 2: matching host,     matching port. */
        int protround;

        for (protround = 1; protround <= 2; ++protround) {
            /* Proto 0: TCP.
             * Proto 1: UDP. */
            struct per_proto *protdata;

            /* Setup */
            map = avahi_natpm_map_create();
            if (map == NULL)
                OOM();

            protdata = (protround == 1) ? &map->tcp : &map->udp;

            map->private_addr = (round == 1) ? host + 1 : host;
            protdata->private_port = (round == 0) ? port + 1 : port;
            protdata->state = PORT_MAPPED;

            REQUIRE_INIT(avahi_natpm_maplist_add(map), 0);

            result = avahi_natpm_maplist_find_hostportproto(host, port, protround == 1 ? NATPMP_PROTO_TCP : NATPMP_PROTO_UDP);
            if (round == 0 || round == 1)
                TEST_EXPECT_PTR(result, NULL);
            else
                TEST_EXPECT_PTR(result, (const void*)map);

            avahi_natpm_maplist_remove_all();
        }
    }

    avahi_natpm_maplist_cleanup();
    
    return failures;
}

int test_expiry(void) {
    int failures = 0;
    int round;
    AvahiNatpmMap *map;
    time_t now;
    
    REQUIRE_INIT(avahi_natpm_maplist_init(), 0);

    TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)-1);

    for (round = 0; round < 3; ++round) {
        /* Round 0: expired, TCP.
         * Round 1: This second, UDP.
         * Round 2: One day from now (not expired), UDP. */
        map = avahi_natpm_map_create();
        now = time(NULL);

        if (!map)
            OOM();

        if (round == 0) {
            map->tcp.state = PORT_MAPPED;
            map->tcp.expiry = now - 1;
        } else {
            map->udp.state = PORT_MAPPED;
        }

        if (round == 1)
            map->udp.expiry = now;
        else if (round == 2)
            map->udp.expiry = now + 86400;

        REQUIRE_INIT(avahi_natpm_maplist_add(map), 0);

        /* I am a bit sleepy, but I think this does not really test much */
        if (round == 0)
            TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(now - 1));
        else if (round == 1)
            TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)now);
        else if (round == 2)
            TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(now + 86400));

        avahi_natpm_maplist_remove_all();
    }

    /* Check that the timer is updated on remove() and remove_all() */
    {
        AvahiNatpmMap *maps[3];
        int i;

        now = time(NULL);

        for (i = 0; i < 3; ++i) {
            maps[i] = avahi_natpm_map_create();
            if (maps[i] == NULL)
                OOM();
            maps[i]->udp.state = PORT_MAPPED;
        }

        maps[0]->udp.expiry = now + 2;
        maps[1]->udp.expiry = now + 1;
        /* This one is TCP for better test coverage */
        maps[2]->tcp.state = PORT_MAPPED;
        maps[2]->udp.state = PORT_UNMAPPED;
        maps[2]->tcp.expiry = now + 0;

        /* Add 1 */
        REQUIRE_INIT(avahi_natpm_maplist_add(maps[0]), 0);
        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(now + 2));

        /* Remove 1 */
        REQUIRE_INIT(avahi_natpm_maplist_remove(maps[0]), 0);
        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)-1);

        /* Add 2 */
        REQUIRE_INIT(avahi_natpm_maplist_add(maps[2]), 0);
        REQUIRE_INIT(avahi_natpm_maplist_add(maps[1]), 0);
        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)(now + 0));

        /* Remove newer 1 */
        REQUIRE_INIT(avahi_natpm_maplist_remove(maps[2]), 0);
        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)(now + 1));

        /* Remove all */
        avahi_natpm_maplist_remove_all();
        TEST_EXPECT_INT((int)avahi_natpm_maplist_next_expiration(), (int)(time_t)-1);
    }

    avahi_natpm_maplist_cleanup();

    return failures;
}

/* vim: ts=4 sw=4 et tw=80
 */
