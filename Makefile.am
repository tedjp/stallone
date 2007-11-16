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

include $(top_srcdir)/Makefile.am.common

SUBDIRS = \
      avahi-common \
      man \
      tests \
      testclient \
   # end

TESTS = \
        $(check_PROGRAMS) \
        # end

AM_CPPFLAGS = \
    -I$(top_srcdir) \
    -DNATPMD_DEFAULT_CONFIG_FILE=\"$(NATPMD_DEFAULT_CONFIG_FILE)\" \
    -DNATPMD_DEFAULT_MAPPING_SCRIPT=\"$(NATPMD_DEFAULT_MAPPING_SCRIPT)\" \
    -DNATPMD_DEFAULT_MIN_PORT=$(NATPMD_DEFAULT_MIN_PORT) \
    -DNATPMD_DEFAULT_MAX_PORT=$(NATPMD_DEFAULT_MAX_PORT) \
    -DNATPMD_CHROOT_DIR=\"$(NATPMD_CHROOT_DIR)\" \
    # end

sbin_PROGRAMS = stallone
check_PROGRAMS = \
                 test-caps \
                 test-natpmd-config \
                 # end

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
                    -DNATPMD_DEFAULT_CONFIG_FILE=\"$(NATPMD_DEFAULT_CONFIG_FILE)\" \
                    # end

test_caps_SOURCES = \
                    caps.c caps.h \
                    test-caps.c \
                    # end

test_caps_LDADD = \
                  $(LIBDAEMON_LIBS) \
                  #end

test_natpmd_config_SOURCES = \
                             test-natpmd-config.c \
                             natpmd-config.c natpmd-config.h \
                             # end
test_natpmd_config_LDADD = \
                           $(LIBDAEMON_LIBS) \
                           $(top_builddir)/avahi-common/libavahi-common.a \
                           # end

test_natpmd_config_CPPFLAGS = \
                              $(AM_CPPFLAGS) \
                              # end

pkgdata_SCRIPTS = natpmd.action

pkgsysconf_DATA = \
                  natpmd.conf \
                  # end

EXTRA_DIST = \
             natpmd.action \
             NEWS \
             INSTALL \
	     THANKS \
             natpmd.conf.in \
	     extras/monit/stallone \
             # end

natpmd.conf: natpmd.conf.in
	sed \
	    -e 's,@NATPMD_DEFAULT_MAPPING_SCRIPT@,$(NATPMD_DEFAULT_MAPPING_SCRIPT),g' \
	    -e 's,@NATPMD_DEFAULT_MIN_PORT@,$(NATPMD_DEFAULT_MIN_PORT),g' \
	    -e 's,@NATPMD_DEFAULT_MAX_PORT@,$(NATPMD_DEFAULT_MAX_PORT),g' \
	    < $^ > $@

CLEANFILES = \
			 natpmd.conf \
			 #

# vim: ts=8 sw=4 tw=80
