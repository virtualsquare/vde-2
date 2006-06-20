#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(vde, [2.1.0], renzo@cs.unibo.it)
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
AC_CHECK_LIB([dl], [dlopen], [crypto])

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
AC_CHECK_FUNCS([atexit dup2 gethostbyname gethostname gettimeofday inet_ntoa memmove memset putenv select setenv socket strchr strdup strerror strstr uname inet_aton sprintf readv random srandom index bcmp drand48 memmove gethostid revoke fchmod getopt_long_only])

# All other nice checks I have to make for recostructing missing parts of
# slirp's config.h file
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char *)

# Define VDE_LINUX or VDE_DARWIN
case "$build_os" in
	linux*)
		AC_DEFINE([VDE_LINUX], 1, [If defined, this is a Linux system])
		;;
	darwin*)
		AC_DEFINE([VDE_DARWIN], 1, [If defined, this is a Darwin system])
		;;
	*)
		AC_MSG_ERROR([Unsupported architecture: $build_os. At the moment, only
Linux and Darwin are supported. Contributions are appreciated! :-)])
		;;
esac

# Check of tuntap device
AC_ARG_ENABLE([tuntap],
    AS_HELP_STRING([--disable-tuntap],
      [Disable tuntap compilation]),
    [if test $enableval != "no" ; then add_tuntap_support=yes ; else add_tuntap_support=no ; fi],
    [add_tuntap_support=yes])

# Check for tuntap support for Linux and OSX
if test "$add_tuntap_support" = yes ; then
	case "$build_os" in
		linux*)
			AC_CHECK_HEADER([linux/if_tun.h],
				[AC_DEFINE([TUNTAP], 1, [If defined, tuntap support is compiled in])],
				[AC_MSG_ERROR([Tuntap support seem to be not enabled on your kernel])])
			can_make_libvdetap=yes
			;;
		darwin*)
			# I don't use AC_CHECK_FILES because I need test -e and not test -r
			for i in /dev/tap0 /Library/Extensions/tap.kext /System/Library/Extensions/tap.kext ; do
				AC_MSG_CHECKING([for $i])
				if test -e "$i" ; then
					AC_MSG_RESULT([yes])
					definename="`echo "$i" | tr "a-z*" "A-ZP" | tr -c "0-9A-Z" "_"`"
					AC_DEFINE_UNQUOTED([HAVE_$definename])
					eval HAVE_$definename=yes
				else
					AC_MSG_RESULT([no])
				fi
			done
			
			if test "$HAVE__DEV_TAP0_" ; then
				AC_DEFINE([TUNTAP], 1, [If defined, tuntap support is compiled in])
				if ! test "$HAVE__LIBRARY_EXTENSIONS_TAP_KEXT_" -o "$HAVE__SYSTEM_LIBRARY_EXTENSIONS_TAP_KEXT_" ; then
					AC_MSG_WARN([/dev/tap0 exists, but the kext cannot be found. Let's hope your
configuration does work...])
				fi
				AC_MSG_CHECKING([for broken poll() support in Tiger])
				if expr "$build_os" : "darwin8\..*" > /dev/null; then
					AC_MSG_RESULT([yes, emulating with select()])
					AC_DEFINE([HAVE_BROKEN_POLL], 1, [If defined, use poll2select])
					have_broken_poll=yes
				else
					AC_MSG_RESULT([no])
				fi
			else
				AC_MSG_ERROR([You do not have tuntap support. You can get it here:
http://www-user.rhrk.uni-kl.de/~nissler/tuntap/])
			fi
			;;
	esac
fi

AM_CONDITIONAL(WANT_TUNTAP, test "$add_tuntap_support" = yes)
AM_CONDITIONAL(CAN_MAKE_LIBVDETAP, test "$can_make_libvdetap" = yes)
AM_CONDITIONAL(HAVE_BROKEN_POLL, test "$have_broken_poll" = yes)

AC_CONFIG_FILES([Makefile]
                [doc/Makefile]
                [qemu/Makefile]
                [slirpvde/Makefile]
                [vdetaplib/Makefile]
                [libvdeplug/Makefile]
                [vde_plug/Makefile]
                [vde_cryptcab/Makefile]
                [bochs/Makefile]
                [dpipe/Makefile]
                [unixterm/Makefile]
                [wirefilter/Makefile]
                [uml/Makefile])
AC_OUTPUT
