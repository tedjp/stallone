/***
  This file is part of Stallone.
 
  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.
 
  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "maplist.h"

/**
 * This whole file is a mess and the API probably sucks.
 */


/* How many results to allocate room for on the first allocation */
#ifndef INITIAL_ALLOC /* To assist testing */
# define INITIAL_ALLOC 10
#endif


static int initialised = 0;

/* Cache/state variables */
static int map_count = -1;

static AVAHI_LLIST_HEAD(AvahiNatpmMap, list_head);

static time_t map_insert(AvahiNatpmMap *map);

/* find callbacks */
static int map_has_expired(const AvahiNatpmMap *map, const void *timeout) AVAHI_GCC_PURE;
static int map_host_matches(const AvahiNatpmMap *map, const void *hostaddr) AVAHI_GCC_PURE;

static int avahi_natpm_maplist_find(
        const void *criteria,
        int (*find_cb)(const AvahiNatpmMap *map, const void *criteria),
        AvahiNatpmMap ***results) AVAHI_GCC_PURE;


/**
 * Initialise the map listing functions.
 *
 * Returns 0 on success, -1 if map listing has already been initialised.
 */
int avahi_natpm_maplist_init(void) {
    if (initialised)
        return -1;

    AVAHI_LLIST_HEAD_INIT(AvahiNatpmMap, list_head);

    map_count = 0;
    initialised = 1;

    return 0;
}

/**
 * Determine whether there are expired mappings.
 * This function is really fast.
 */
int avahi_natpm_maplist_has_expired_items(void) {
    return (list_head && avahi_natpm_map_next_expiry(list_head) <= time(NULL));
}

void avahi_natpm_maplist_cleanup(void) {

    if (!initialised)
        return;

    avahi_natpm_maplist_remove_all();

    initialised = 0;
    map_count = -1;
}

/**
 * Adds a map.
 *
 * Returns -1 if the maplist has not been initialised yet or zero if everything
 * went OK.
 */
int avahi_natpm_maplist_add(AvahiNatpmMap *map) {

    assert(map != NULL);

    if (!initialised)
        return -1;

    AVAHI_LLIST_INIT(AvahiNatpmMap, map, map);

    map_insert(map);

    ++map_count;

    return 0;
}

/**
 * Removes the selected map from the map list. The caller is responsible for
 * freeing the map if required.
 *
 * The map item must already be in the list or this function is likely to
 * assert().
 *
 * Returns -1 if the maplist has not been initialised, or 0 on success.
 */
int avahi_natpm_maplist_remove(AvahiNatpmMap *map) {

    assert(map != NULL);

    if (!initialised)
        return -1;

    AVAHI_LLIST_REMOVE(AvahiNatpmMap, map, list_head, map);

    avahi_natpm_map_destroy(map);

    --map_count;

    return 0;
}

/**
 * Returns a const pointer to the first mapping in the list, or NULL if there
 * are no items.
 */
const AvahiNatpmMap *avahi_natpm_maplist_peek(void) {
    return list_head;
}

int avahi_natpm_maplist_count(void) {

    if (!initialised)
        return -1;

    return map_count;
}

void avahi_natpm_maplist_remove_all(void) {

    if (!initialised)
        return;

    while (list_head)
        AVAHI_LLIST_REMOVE(AvahiNatpmMap, map, list_head, list_head);

    map_count = 0;
}

/**
 * Determine whether the given map has timed out according to timeout.
 * @return 1 if the map has timed out, else 0.
 */
int map_has_expired(const AvahiNatpmMap *map, const void *timeout) {
    const time_t exp = *(const time_t *)timeout;

    if (map->tcp.state == PORT_MAPPED && map->tcp.expiry <= exp)
        return 1;

    if (map->udp.state == PORT_MAPPED && map->udp.expiry <= exp)
        return 1;

    return 0;
}

/**
 * Get a list of all the mappings that have expired.
 * @param results       [out] Pointer to array of pointers
 * @return Number of results or -1 on error.
 */
int avahi_natpm_maplist_find_expired(AvahiNatpmMap ***results) {
    const time_t now = time(NULL);

    assert(results != NULL);

    return avahi_natpm_maplist_find(&now, map_has_expired, results);
}

int map_host_matches(const AvahiNatpmMap *map, const void *hostaddr) {
    return (map->private_addr == (*(const in_addr_t*)hostaddr));
}

/**
 * Get a list of mappings that go to the specified host address.
 */
int avahi_natpm_maplist_find_byhost(in_addr_t hostaddr, AvahiNatpmMap ***results) {
    return avahi_natpm_maplist_find(&hostaddr, map_host_matches, results);
}

AvahiNatpmMap *avahi_natpm_maplist_find_by_pub_port(uint16_t pub_port) {
    AvahiNatpmMap *it;

    for (it = list_head; it; it = it->map_next) {
        if (it->public_port == pub_port)
            return it;
    }

    return NULL;
}

AvahiNatpmMap *avahi_natpm_maplist_find_hostport(in_addr_t host, uint16_t priv_port, AvahiNPProto proto) {
    AvahiNatpmMap *it;

    for (it = list_head; it; it = it->map_next) {
        if (it->private_addr != host)
            continue;
        if (proto == NATPMP_MAP_TCP && it->tcp.state == PORT_MAPPED && it->tcp.private_port == priv_port)
            return it;
        if (proto == NATPMP_MAP_UDP && it->udp.state == PORT_MAPPED && it->udp.private_port == priv_port)
            return it;
    }

    return NULL;
}

/**
 * The next time a map will expire.
 * Returns -1 if there are no maps at all.
 * Values in the range [0,now] indicate an already-expired map is in the list,
 * so be careful you don't just subtract the current time from this to figure
 * out when the next one expires, or you will get a negative result.
 *
 * This is currently inefficient because it walks the tree on each call.
 */
time_t avahi_natpm_maplist_next_expiration(void) {
    if (list_head)
        return avahi_natpm_map_next_expiry(list_head);
    else
        return -1;
#if 0 /* Old */
    AvahiNatpmMap *it;
    time_t next_expiry;

    if (map_count < 1) {
        next_expiry = -1;
        return -1;
    }

    assert(list_head);

    it = list_head;
    if (it->tcp.state == PORT_MAPPED)
        next_expiry = it->tcp.expiry;
    else
        next_expiry = it->udp.expiry;

    for ( ; it; it = it->map_next) {
        if (it->tcp.state == PORT_MAPPED && it->tcp.expiry < next_expiry)
            next_expiry = it->tcp.expiry;
        if (it->udp.state == PORT_MAPPED && it->udp.expiry < next_expiry)
            next_expiry = it->udp.expiry;
    }

    return next_expiry;
#endif
}

/**
 * Update the lifetime of a particular map.
 *
 * Returns the time of next expiration (like
 * avahi_natpm_maplist_next_expiration()).
 *
 * The map must already be in the list.
 *
 * Returns (time_t)-1 if there are no maps.
 *
 * XXX: This function needs unit testing.
 */
time_t avahi_natpm_maplist_update_lifetime(AvahiNatpmMap *map, AvahiNPProto proto, uint32_t lifetime) {
    const time_t expiry = time(NULL) + lifetime;
    time_t initial_exp, new_exp;

    assert(initialised);
    assert(map_count > 0);
    assert(list_head); /* Nothing is being added or removed, only moved. */

    initial_exp = avahi_natpm_map_next_expiry(map);

    if (proto == NATPMP_MAP_TCP) {
        map->tcp.expiry = expiry;

        if (map->udp.state == PORT_MAPPED && map->udp.expiry < expiry)
            new_exp = map->udp.expiry;
        else
            new_exp = expiry;
    } else {
        map->udp.expiry = expiry;

        if (map->tcp.state == PORT_MAPPED && map->tcp.expiry < expiry)
            new_exp = map->tcp.expiry;
        else
            new_exp = expiry;
    }

    if (list_head == map && list_head->map_next == NULL) {
        /* Only one map, don't modify the list. */
        return new_exp;
    }

    /* Remove the map from the list */
    if (map->map_prev) {
        map->map_prev->map_next = map->map_next;
    } else {
        assert(list_head == map);
        list_head = NULL;
    }
    if (map->map_next)
        map->map_next->map_prev = map->map_prev;

    /* Don't leave dangling pointers */
    map->map_next = NULL;
    map->map_prev = NULL;

    return map_insert(map);
}

/**
 * Insert the specified map into the linked list.
 * It must not already be in the list.
 * It will be put in a position where the list ordering is maintained.
 * It is the caller's responsibility to increment the map_count.
 */
static time_t map_insert(AvahiNatpmMap *map) {
    AvahiNatpmMap *it, *prev = NULL;

    assert(map);
    
    /* Ensure the map doesn't have dangling pointers */
    map->map_next = NULL;
    map->map_prev = NULL;
    
    if (!list_head) {
        /* The only list entry */
        list_head = map;
        return avahi_natpm_map_next_expiry(list_head);
    }

    if (avahi_natpm_map_next_expiry(map) < avahi_natpm_map_next_expiry(list_head)) {
        /* This is the new soonest-expiry */
        map->map_next = list_head;
        map->map_next->map_prev = map;

        list_head = map;
        return avahi_natpm_map_next_expiry(map);
    }

    /* Find out where the map should go now */
    for (it = list_head; it; it = it->map_next) {

        if (avahi_natpm_map_next_expiry(map) >= avahi_natpm_map_next_expiry(it)) {
            map->map_prev = it;
            map->map_next = it->map_next;

            if (it->map_next)
                it->map_next->map_prev = map;

            it->map_next = map;

            break;
        }

        prev = it;
    }

    return avahi_natpm_map_next_expiry(list_head);
}

/**
 * Find matching maps according to the provided match callback.
 * @param criteria Criteria data passed to the match callback.
 * @param find_cb The match callback. Returns 1 on match, else 0.
 * @param results A dynamically allocated array of pointers to matching maps.
 *                Do not use the map_prev and map_next members of the maps.
 *                If this function returns >= 1, this memory must be freed with
 *                avahi_natpm_maplist_free_result().
 *                If it returns 0 and none were found, this will be NULL.
 *                If an error code is returned, the contents of this pointer are
 *                undefined and must not be freed.
 * @return Number of maps found, or -1 on error.
 */
int avahi_natpm_maplist_find(
        const void *criteria,
        int (*find_cb)(const AvahiNatpmMap *map, const void *criteria),
        AvahiNatpmMap ***results)
{
    AvahiNatpmMap *it, **dest = NULL;
    /* These could be made file-scope static and the allocation could be reused
     * to avoid thrashing the heap. */
    int count = 0, allocnum;

    if (!initialised)
        return -1;

    for (it = list_head; it; it = it->map_next) {
        if (find_cb(it, criteria)) {
            if (count == 0) { /* First match */
                dest = malloc((allocnum = INITIAL_ALLOC) * sizeof(*dest));
                if (!dest)
                    return -1;
            } else if (count + 1 > allocnum) { /* Subsequent matches */
                AvahiNatpmMap **newalloc;
                allocnum *= 2;
                newalloc = realloc(dest, allocnum * sizeof(*dest));
                if (!newalloc) {
                    /* Don't send a partial list of matches, return error. */
                    free(dest);
                    return -1;
                }
                /* realloc went OK */
                dest = newalloc;
            }
            dest[count] = it;
            ++count;
        }
    }

    *results = dest;
    return count;
}

/**
 * Frees the result array.
 * Does not free the individual maps.
 * @param result result to free. May be NULL.
 */
void avahi_natpm_maplist_free_result(AvahiNatpmMap **result) {
    if (result)
        free(result);
}

/* vim: ts=4 sw=4 et tw=80
 */
