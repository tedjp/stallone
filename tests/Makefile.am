# This file is part of Stallone
# Copyright 2007  Ted Percival <ted@midg3t.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.

if DEVELOPER_MODE
COVERAGE_FLAGS = --coverage
endif

TESTS = \
    test_maplist \
    test_natmap \
    test_interface_vis \
    # end

check_PROGRAMS = \
		  $(TESTS)

AM_CPPFLAGS = \
              -I$(top_srcdir) \
              #endf

test_maplist_SOURCES = test_maplist.c ../natmap.c ../maplist.c ../maplist.h
test_maplist_CFLAGS = $(AM_CFLAGS) -DINITIAL_ALLOC=1 $(COVERAGE_FLAGS)
test_maplist_LDFLAGS = $(AM_LDFLAGS) $(COVERAGE_FLAGS)

test_natmap_SOURCES = test_natmap.c ../natmap.c ../natmap.h
test_natmap_CFLAGS = $(AM_CFLAGS) $(COVERAGE_FLAGS)
test_natmap_LDFLAGS = $(AM_LDFLAGS) $(COVERAGE_FLAGS)

clean-local:
	rm -f *.gcda *.gcno *.gcov

coverage: check
	gcov -o test_maplist-maplist.gcda ../maplist.c
	gcov -o test_natmap-natmap.gcda ../natmap.c
	rm -f sysmacros.h*

test_interface_vis_SOURCES = test-interface-vis.c ../interface.c ../interface.h

test_interface_vis_CFLAGS = $(AM_CPPFLAGS)

test_interface_vis_LDADD = $(AM_LDADD) $(LIBDAEMON_LIBS) \
                           $(top_builddir)/avahi-common/libavahi-common.a

.PHONY: coverage

# vim: ts=4 sw=4 tw=80
