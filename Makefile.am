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

SUBDIRS = \
      avahi-common \
      tests \
      testclient \
   # end

TESTS = \
        $(check_PROGRAMS) \
        # end


pkgsysconfdir = $(sysconfdir)/avahi

AM_CPPFLAGS = \
    -I$(top_srcdir) \
    -DAVAHI_NATPMD_CONFIG_FILE=\"$(pkgsysconfdir)/avahi-natpmd.conf\" \
    -DAVAHI_NATPMD_ACTION_SCRIPT=\"$(pkgdatadir)/avahi-natpmd.action\" \
    -DAVAHI_NATPMD_CHROOT_DIR=\"$(localstatedir)/avahi-natpmd\" \
    # end

sbin_PROGRAMS = stallone
check_PROGRAMS = test-caps

stallone_SOURCES = \
                       caps.c caps.h \
                       common.c common.h \
                       interface.c interface.h \
                       ipc.c ipc.h \
                       maplist.c maplist.h \
                       natmap.c natmap.h \
                       natpmd.c \
                       natpmd-config.c natpmd-config.h \
                       packetdump.c packetdump.h \
                       timer.c timer.h \
                       worker.c worker.h \
                       # end of list

stallone_LDADD = \
                     $(LIBDAEMON_LIBS) \
                     $(top_builddir)/avahi-common/libavahi-common.a

stallone_CPPFLAGS = \
                    $(AM_CPPFLAGS) \
                    -DNATPMD_DEFAULT_CONFIG_FILE=\"$(pkgsysconfdir)/natpmd.conf\" \
                    # end

test_caps_SOURCES = \
                    caps.c caps.h \
                    test-caps.c \
                    # end

test_caps_LDADD = \
                  $(LIBDAEMON_LIBS) \
                  #end

pkgdata_SCRIPTS = avahi-natpmd.action

stallone.8.html: stallone.8.txt
	asciidoc -d manpage stallone.8.txt

EXTRA_DIST = avahi-natpmd.action stallone.8.txt stallone.8.html NEWS

# vim: ts=4 sw=4 et tw=80 list
