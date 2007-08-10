# $Id$

# This file is part of avahi.
#
# avahi is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# avahi is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with avahi; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.

SUBDIRS = \
	  avahi-common \
	  tests \
	  # end

pkgsysconfdir = $(sysconfdir)/avahi

AM_CPPFLAGS = \
    -DAVAHI_NATPMD_CONFIG_FILE=\"$(pkgsysconfdir)/avahi-natpmd.conf\" \
    -DAVAHI_NATPMD_ACTION_SCRIPT=\"$(pkgdatadir)/avahi-natpmd.action\" \
    -DAVAHI_NATPMD_CHROOT_DIR=\"$(localstatedir)/avahi-natpmd\" \
    -DAVAHI_PM_SOCKET=\"$(avahi_pm_socket)\" # XXX: Is this even used?

sbin_PROGRAMS = avahi-natpmd

avahi_natpmd_SOURCES = \
                       common.c common.h \
                       interface.c interface.h \
                       ipc.c ipc.h \
                       maplist.c maplist.h \
                       natmap.c natmap.h \
                       natpmd.c \
                       packetdump.c packetdump.h \
                       timer.c timer.h \
                       worker.c worker.h \
                       # end of list

avahi_natpmd_LDADD = \
                     $(LIBDAEMON_LIBS) -lcap \
                     $(top_builddir)/avahi-common/libavahi-common.a

pkgdata_SCRIPTS = avahi-natpmd.action

EXTRA_DIST = avahi-natpmd.action

# vim:ts=4:sw=4:et:tw=80
