#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_INIT([vdetelweb], [1.1b], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([vdetelweb.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h string.h sys/ioctl.h sys/socket.h syslog.h lwipv6.h],, AC_MSG_ERROR([required header file missing]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit bzero getcwd memset socket strdup strerror strndup strstr uname])

# Checks for libraries.
AC_CHECK_LIB([lwipv6], [lwip_init],, AC_MSG_ERROR([liblwipv6 missing]), [-lpthread])
AC_CHECK_LIB([ssl], [SHA1_Init],, AC_MSG_ERROR([libssl (openssl) missing]), [-lssl])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
