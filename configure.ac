#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
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

AC_PREREQ(2.61)
AC_INIT([stallone], [0.1.0], [ted @ midg3t.net])
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([foreign check-news -Wall])
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
# For libavahi-common
AC_PROG_RANLIB
# Used for tests/coverage
AM_PROG_CC_C_O

AC_CHECK_HEADER([sys/capability.h])

AC_CHECK_LIB([cap], [cap_init], [LIBS="$LIBS -lcap"])

PKG_CHECK_MODULES([LIBDAEMON], [libdaemon >= 0.5])
AC_SUBST(LIBDAEMON_CFLAGS)
AC_SUBST(LIBDAEMON_LIBS)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h malloc.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_CHECK_FUNCS([\
                alarm \
                gettimeofday \
                memset \
                mkdir \
                select \
                setegid \
                seteuid \
                setregid \
                setresgid \
                setresuid \
                setreuid \
                socket \
                strcasecmp \
                strerror \
                strrchr \
                strtol \
                ])

dnl TODO: Make this configurable
dnl AC_DEFINE_UNQUOTED(NATPMD_DEFAULT_CONFIG_FILE, "$pkgsysconfdir/natpmd.conf",
dnl                   [Configuration file location])

#
# Avahi-natpmd users & groups
#
AC_ARG_WITH(natpmd_user, AS_HELP_STRING([--with-natpmd-user=<user>],[User for the daemon to run as by default (default=nobody)]))
if test -z "$with_natpmd_user" ; then
    AVAHI_NATPMD_USER=nobody
else
    AVAHI_NATPMD_USER=$with_natpmd_user
fi
AC_SUBST(AVAHI_NATPMD_USER)
AC_DEFINE_UNQUOTED(AVAHI_NATPMD_USER,"$AVAHI_NATPMD_USER", [User for the daemon to run as by default])

AC_ARG_WITH(natpmd_group,AS_HELP_STRING([--with-natpmd-group=<group>],[Group for the daemon to run as by default (default=nogroup)]))
if test -z "$with_natpmd_group" ; then
    AVAHI_NATPMD_GROUP=nogroup
else
    AVAHI_NATPMD_GROUP=$with_natpmd_group
fi
AC_SUBST(AVAHI_NATPMD_GROUP)
AC_DEFINE_UNQUOTED(AVAHI_NATPMD_GROUP,"$AVAHI_NATPMD_GROUP", [iGroup for the daemon to run as by default])


AC_CONFIG_FILES([Makefile
                 tests/Makefile
                 testclient/Makefile
                 avahi-common/Makefile])
AC_OUTPUT

# vim: ts=4 sw=4 et
