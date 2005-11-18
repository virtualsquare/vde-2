#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(vde, [1.5.10], renzo@cs.unibo.it)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([vde.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h termio.h termios.h unistd.h sys/filio.h sys/bitypes.h sys/wait.h sys/select.h sys/signal.h sys/stropts.h termios.h sys/type32.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_C_PROTOTYPES
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit dup2 gethostbyname gethostname gettimeofday inet_ntoa memmove memset putenv select setenv socket strchr strdup strerror strstr uname inet_aton sprintf readv random srandom index bcmp drand48 memmove gethostid revoke fchmod])

# All other nice checks I have to make for recostructing missing parts of
# slirp's config.h file
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char *)

# Check of tuntap device
AC_ARG_ENABLE([tuntap],
    AS_HELP_STRING([--disable-tuntap],
      [Disable tuntap compilation]),
    [if test $enableval != "no" ; then add_tuntap_support=yes ; else add_tuntap_support=no ; fi],
    [add_tuntap_support=yes])

AM_CONDITIONAL(WANT_TUNTAP, test "$add_tuntap_support" = yes)
if test "$add_tuntap_support" = yes ; then
  AC_CHECK_HEADER([linux/if_tun.h],
      [AC_DEFINE([TUNTAP], 1, [If defined, tuntap support is compiled in])],
      [AC_MSG_ERROR([Tuntap support seem to be not enabled on your kernel])])
fi

#AC_CONFIG_FILES([doc/Makefile
#                 qemu/Makefile
#                 slirpvde/Makefile
#                 vdetaplib/Makefile])
AC_CONFIG_FILES([Makefile]
                [doc/Makefile]
                [qemu/Makefile]
                [slirpvde/Makefile]
                [vdetaplib/Makefile]
                [bochs/Makefile]
                [uml/Makefile])
AC_OUTPUT
