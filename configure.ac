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
AC_INIT([stallone], [0.4.0], [ted @ midg3t.net])
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_LIBOBJ_DIR([lib])
AM_INIT_AUTOMAKE([foreign check-news -Wall subdir-objects])

AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

AC_PATH_PROG([A2X], [a2x])
AM_CONDITIONAL([HAVE_A2X], [test -n "$A2X"])

# Used for tests/coverage
AM_PROG_CC_C_O

AC_ARG_ENABLE([developer-mode],
              [AS_HELP_STRING([--enable-developer-mode],
                              [Turns on stricter compiler options])])
AM_CONDITIONAL([DEVELOPER_MODE], [test "$enable_developer_mode" = "yes"])

if test "x$GCC" = "xyes"; then
    DESIRED_CFLAGS="-Wall -Wextra -std=c99 -g"
    DESIRED_LDFLAGS="-Wl,-z,defs"

    # Add stricter flags in developer mode
    if test "$enable_developer_mode" = "yes"; then
        DESIRED_CFLAGS="$DESIRED_CFLAGS -pedantic-errors -Werror"
    fi

    for flag in $DESIRED_CFLAGS; do
        AC_MSG_CHECKING([whether ${CC} accepts ${flag}])
        orig_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $flag"

        AC_COMPILE_IFELSE([int main() {}],
                          [AC_MSG_RESULT([yes])],
                          [AC_MSG_RESULT([no])
                           CFLAGS="$orig_CFLAGS"])
    done

    for flag in $DESIRED_LDFLAGS; do
        AC_MSG_CHECKING([whether ${CC} accepts ${flag}])
        orig_LDFLAGS="$LDFLAGS"
        LDFLAGS="$LDFLAGS $flag"

        AC_LINK_IFELSE([int main() {}],
                       [AC_MSG_RESULT([yes])],
                       [AC_MSG_RESULT([no])
                        LDFLAGS="$orig_LDFLAGS"])
    done
fi

AC_CHECK_HEADERS([sys/capability.h])

AC_CHECK_LIB([cap], [cap_init])

PKG_CHECK_MODULES([LIBDAEMON], [libdaemon >= 0.5])
AC_SUBST(LIBDAEMON_CFLAGS)
AC_SUBST(LIBDAEMON_LIBS)
AC_CHECK_LIB([daemon], [daemon_log])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([\
                  arpa/inet.h \
                  fcntl.h \
                  limits.h \
                  malloc.h \
                  netinet/in.h \
                  stdint.h \
                  stdlib.h \
                  string.h \
                  sys/ioctl.h \
                  sys/prctl.h \
                  sys/socket.h \
                  sys/time.h \
                  unistd.h\
                  ])

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
dnl More trouble than they're worth. Just don't call malloc(0) and
dnl everything will be fine.
dnl AC_FUNC_MALLOC
dnl AC_FUNC_REALLOC
dnl AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
dnl To be added in future
dnl AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_CHECK_FUNCS([\
                alarm \
                atexit \
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
                strchr \
                strcspn \
                strerror \
                strrchr \
                strspn \
                strtol \
                ])

#
# Avahi-natpmd users & groups
#
AC_ARG_WITH(natpmd_user, AS_HELP_STRING([--with-natpmd-user=<user>],[User for the daemon to run as by default (default=nobody)]))
if test -z "$with_natpmd_user" ; then
    NATPMD_USER=nobody
else
    NATPMD_USER=$with_natpmd_user
fi
AC_SUBST(NATPMD_USER)
AC_DEFINE_UNQUOTED(NATPMD_USER,"$NATPMD_USER", [User for the daemon to run as by default])

AC_ARG_WITH(natpmd_group,AS_HELP_STRING([--with-natpmd-group=<group>],[Group for the daemon to run as by default (default=nogroup)]))
if test -z "$with_natpmd_group" ; then
    NATPMD_GROUP=nogroup
else
    NATPMD_GROUP=$with_natpmd_group
fi
AC_SUBST(NATPMD_GROUP)
AC_DEFINE_UNQUOTED(NATPMD_GROUP,"$NATPMD_GROUP", [Group for the daemon to run as by default])

AC_CONFIG_FILES([Makefile
                 tests/Makefile
                 testclient/Makefile
                 avahi-common/Makefile
                 man/Makefile
                 lib/Makefile
                 ])
AC_OUTPUT

# vim: ts=4 sw=4 et
