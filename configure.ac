#                                               -*- Autoconf -*-/
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([vde2],[2.3.3],[info@v2.cs.unibo.it])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign dist-bzip2 subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([include/vde.h])
AC_CONFIG_LIBOBJ_DIR(src/common)
AC_CONFIG_HEADERS([include/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
LT_INIT
AM_PROG_CC_C_O

AC_DEFINE_UNQUOTED(MODULES_EXT, "$shrext_cmds", [Extension of shared objects])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([wolfssl], [wc_Chacha_Process],
  [add_cryptcab_support=yes],
  [add_cryptcab_support=no ; warn_cryptcab=yes])
AC_CHECK_LIB([pthread], [pthread_create],
  [enable_router=yes],
  [enable_router=no ; warn_router=yes])
AC_CHECK_LIB([pcap], [pcap_open_dead],
  [add_pcap=yes],
  [add_pcap=no ; warn_pcap=yes])

# Checks for header files.
AC_PROG_EGREP

AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h \
  stdlib.h string.h strings.h sys/ioctl.h sys/param.h sys/socket.h \
  sys/time.h syslog.h termio.h termios.h unistd.h sys/filio.h sys/bitypes.h \
  sys/wait.h sys/select.h sys/signal.h sys/stropts.h termios.h sys/type32.h])

AC_CHECK_HEADERS([syslimits.h sys/syslimits.h])

AC_CHECK_HEADERS([wolfssl/wolfcrypt/chacha.h], [],
  [add_cryptcab_support=no ; warn_cryptcab=yes])

AC_CHECK_HEADERS([sysexits.h],
  [add_over_ns_support=yes],
  [add_over_ns_support=no ; warn_over_ns=yes])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_C_PROTOTYPES
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit dup2 gethostbyname gethostname gettimeofday inet_ntoa \
  memmove memset putenv select setenv socket strchr strdup strerror strstr \
  uname inet_aton sprintf readv random srandom index bcmp drand48 memmove \
  gethostid revoke fchmod getopt_long_only funopen])
AC_REPLACE_FUNCS([open_memstream strndup])
AC_CHECK_FUNC([poll],
  [
    AC_MSG_CHECKING([for poll sanity])
    if expr "$build_os" : "darwin*" > /dev/null; then
      AC_MSG_RESULT([present but broken, emulating with select])
      AC_LIBOBJ([poll])
      AC_DEFINE([poll], [vde_poll],
                [Define to vde_poll if the replacement function should be used.])
    else
      AC_DEFINE([HAVE_POLL], 1, [Define to 1 if your system has a working poll() function.])
      AC_MSG_RESULT([yes])
    fi
  ],
  [])

# All other nice checks I have to make for recostructing missing parts of
# slirp's config.h file
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char *)

# Define VDE_LINUX or VDE_DARWIN
case "$build_os" in
  linux*)
    if expr "$host_os" : ".*android" > /dev/null; then
      AC_DEFINE([VDE_BIONIC], 1, [If defined, this is a Linux/bionic system])
    else
      AC_DEFINE([VDE_LINUX], 1, [If defined, this is a Linux system])
    fi
  ;;
  darwin*)
    AC_DEFINE([VDE_DARWIN], 1, [If defined, this is a Darwin system])
    darwin_gcc=yes
  ;;
  freebsd*)
    AC_DEFINE([VDE_FREEBSD], 1, [If defined, this is a FreeBSD system])
  ;;
  *)
    AC_MSG_ERROR([Unsupported OS: $build_os. At the moment, only Linux, Darwin
and FreeBSD are supported. Contributions are appreciated! :-)])
  ;;
esac

# Enable profiling options
AC_ARG_ENABLE([profile],
  AS_HELP_STRING([--enable-profile],
    [Compile with debugging/profiling options]),
  [if test $enableval = "yes"; then enable_profile=yes; fi])

# Enable experimental features
AC_ARG_ENABLE([experimental],
  AS_HELP_STRING([--enable-experimental],
    [Enable experimental features (async notifies, plugin support, packet counter)]),
  [if test $enableval = "yes"; then enable_experimental=yes; fi])

# Disable vde_cryptcab? (depends on wolfssl, maybe unwanted)
AC_ARG_ENABLE([cryptcab],
  AS_HELP_STRING([--disable-cryptcab],
    [Disable vde_cryptcab compilation]),
  [if test $enableval = "no" ; then add_cryptcab_support=no ; warn_cryptcab=no ; fi])

# Disable vde_over_ns? (not working on android, maybe unwanted)
AC_ARG_ENABLE([vde_over_ns],
  AS_HELP_STRING([--disable-vde_over_ns],
    [Disable vde_over_ns compilation]),
  [if test $enableval = "no" ; then add_over_ns_support=no ; warn_over_ns=no ; fi])

# Disable vde_router? (depends on lpthread, maybe unwanted)
AC_ARG_ENABLE([router],
  AS_HELP_STRING([--disable-router],
    [Disable libpthread-dependent vde_router compilation]),
  [if test $enableval = "no" ; then enable_router=no ; warn_router=no ; fi])

enable_vxlan=yes
# Disable vde_vxlan?
AC_ARG_ENABLE([vxlan],
  AS_HELP_STRING([--disable-vxlan],
    [Disable vde_vxlan compilation]),
  [if test $enableval = "no" ; then enable_vxlan=no ; warn_vxlan=no ; fi])

# Check of tuntap device
AC_ARG_ENABLE([tuntap],
  AS_HELP_STRING([--disable-tuntap], [Disable tuntap compilation]), [:],
  [case "$build_os" in
    linux*)
      AC_CHECK_HEADER([linux/if_tun.h],
        [AC_DEFINE([HAVE_TUNTAP], 1, [If defined, tuntap support is compiled in])],
        [warn_tuntap=yes])
      can_make_libvdetap=yes
      ;;
    darwin*)
      # I don't use AC_CHECK_FILES because I need test -e and not test -r
      for i in /dev/tap0 /Library/Extensions/tap.kext ; do
        AC_MSG_CHECKING([for $i])
        if test -e "$i" ; then
          AC_MSG_RESULT([yes])
          definename="`echo "$i" | tr "a-z*" "A-ZP" | tr -c "0-9A-Z" "_"`"
          AC_DEFINE_UNQUOTED([HAVE_$definename])
          eval HAVE_$definename=yes
        else
          AC_MSG_RESULT([no])
          warn_tuntap=yes
        fi
      done

      if test "$HAVE__DEV_TAP0_" ; then
        AC_DEFINE([HAVE_TUNTAP], 1, [If defined, tuntap support is compiled in])
        if ! test "$HAVE__LIBRARY_EXTENSIONS_TAP_KEXT_" || "$HAVE__SYSTEM_LIBRARY_EXTENSIONS_TAP_KEXT_" ; then
          AC_MSG_WARN([/dev/tap0 exists, but the kext cannot be found. Let's hope your
configuration does work...])
        fi
      else
        warn_tuntap=yes
        AC_MSG_WARN([You do not have tuntap support. You can get it here:
http://tuntaposx.sourceforge.net/])
      fi
      ;;
    freebsd*)
      AC_CHECK_HEADER([net/if_tun.h],
        [AC_DEFINE([HAVE_TUNTAP], 1, [If defined, tuntap support is compiled in])],
        [warn_tuntap=yes])
      ;;
  esac])

# Disable pcap support (pdump)? (depends on libpcap, maybe unwanted)
AC_ARG_ENABLE([pcap],
  AS_HELP_STRING([--disable-pcap],
    [Disable pcap support (pdump plugin)]),
  [if test $enableval = "no" ; then add_pcap=no ; warn_pcap=no ; fi])

AM_CONDITIONAL(ENABLE_CRYPTCAB, test "$add_cryptcab_support" = yes)
AM_CONDITIONAL(ENABLE_VDE_OVER_NS, test "$add_over_ns_support" = yes)
AM_CONDITIONAL(ENABLE_ROUTER, test "$enable_router" = yes)
AM_CONDITIONAL(ENABLE_PCAP, test "$add_pcap" = yes)
AM_CONDITIONAL(CAN_MAKE_LIBVDETAP, test "$can_make_libvdetap" = yes)
AM_CONDITIONAL(ENABLE_EXPERIMENTAL, test "$enable_experimental" = yes)
AM_CONDITIONAL(ENABLE_PROFILE, test "$enable_profile" = yes)
AM_CONDITIONAL(DARWIN_GCC, test "$darwin_gcc" = yes)


CFLAGS="-Wall -O2 $CFLAGS"
AC_SUBST(CFLAGS)

AC_CONFIG_FILES(
  [Makefile]
  [doc/Makefile]
  [include/Makefile]
  [man/Makefile]
  [src/Makefile]
  [src/lib/Makefile]
  [src/lib/vdesnmp.pc]
  [src/lib/vdeplug.pc]
  [src/lib/vdehist.pc]
  [src/lib/vdemgmt/Makefile]
  [src/lib/vdemgmt/vdemgmt.pc]
  [src/vde_switch/Makefile]
  [src/vde_over_ns/Makefile]
  [src/common/Makefile]
  [src/vdetaplib/Makefile]
  [src/vde_cryptcab/Makefile]
  [src/vde_router/Makefile]
  [src/vde_switch/plugins/Makefile]
)
AC_OUTPUT


AS_ECHO
AS_ECHO
AS_ECHO "Configure results:"
AS_ECHO
if test x$add_cryptcab_support = "xyes" ; then
  AS_ECHO " + VDE CryptCab............ enabled"
else
  AS_ECHO " - VDE CryptCab............ disabled"
fi

if test x$enable_router = "xyes" ; then
  AS_ECHO " + VDE Router.............. enabled"
else
  AS_ECHO " - VDE Router.............. disabled"
fi

if test x$warn_tuntap = "xyes" ; then
  AS_ECHO " - TAP support............. disabled"
else
  AS_ECHO " + TAP support............. enabled"
fi

if test x$add_pcap = "xyes" ; then
  AS_ECHO " + pcap support............ enabled"
else
  AS_ECHO " - pcap support............ disabled"
fi

if test x$enable_experimental = "xyes" ; then
  AS_ECHO " + Experimental features... enabled"
else
  AS_ECHO " - Experimental features... disabled"
fi

if test x$enable_profile = "xyes" ; then
  AS_ECHO " + Profiling options....... enabled"
else
  AS_ECHO " - Profiling options....... disabled"
fi

AS_ECHO
AS_ECHO
if ! test x$add_cryptcab_support = "xyes" ; then
  if test x$warn_cryptcab = "xyes" ; then
    AC_MSG_WARN([VDE CryptCab support has been disabled because wolfSSL is
not installed on your system, or because wolfssl/wolfcrypt/chacha.h could not be found.
Please install libwolfssl if you want CryptCab to be compiled and installed.])
    AS_ECHO
  fi
fi

if ! test x$add_over_ns_support = "xyes" ; then
  if test x$warn_over_ns = "xyes" ; then
    AC_MSG_WARN([VDE vde_over_ns support has been disabled because your libc
    sysexits.h could not be found.])
    AS_ECHO
  fi
fi

if ! test x$enable_router = "xyes" ; then
  if test x$warn_router = "xyes" ; then
    AC_MSG_WARN([VDE Router support has been disabled because libpthread is
not installed on your system.])
    AS_ECHO
  fi
fi

if ! test x$add_pcap = "xyes" ; then
  if test x$warn_pcap = "xyes" ; then
    AC_MSG_WARN([VDE vde_pcapplug and packet dump plugin have been disabled
because libpcap is not installed on your system, or because it is too old.
Please install it if you want vde_pcapplug and pdump to be compiled and
installed.])
    AS_ECHO
  fi
fi

AS_ECHO
AS_ECHO "Type 'make' to compile $PACKAGE $VERSION,"
AS_ECHO "or type 'make V=1' for verbose compiling"
AS_ECHO "and then type 'make install' to install it into $prefix"
AS_ECHO
