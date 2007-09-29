#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([stallone], [0.0.0], [ted@midg3t.net])
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
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

#
# Avahi-natpmd users & groups
#
AC_ARG_WITH(natpmd_user, AS_HELP_STRING([--with-natpmd-user=<user>],[User for running the Avahi NAT port mapping daemon (avahi-natpmd)]))
if test -z "$with_natpmd_user" ; then
    AVAHI_NATPMD_USER=avahi-natpmd
else
    AVAHI_NATPMD_USER=$with_natpmd_user
fi
AC_SUBST(AVAHI_NATPMD_USER)
AC_DEFINE_UNQUOTED(AVAHI_NATPMD_USER,"$AVAHI_NATPMD_USER", [User for running the avahi-natpmd daemon])

AC_ARG_WITH(natpmd_group,AS_HELP_STRING([--with-natpmd-group=<group>],[Group for running the Avahi NAT port mapping daemon (avahi-natpmd)]))
if test -z "$with_natpmd_group" ; then
    AVAHI_NATPMD_GROUP=avahi-natpmd
else
    AVAHI_NATPMD_GROUP=$with_natpmd_group
fi
AC_SUBST(AVAHI_NATPMD_GROUP)
AC_DEFINE_UNQUOTED(AVAHI_NATPMD_GROUP,"$AVAHI_NATPMD_GROUP", [Group for running the avahi-natpmd daemon])


AC_CONFIG_FILES([Makefile
                 tests/Makefile
                 testclient/Makefile
                 avahi-common/Makefile])
AC_OUTPUT

# vim: ts=4 sw=4 et
