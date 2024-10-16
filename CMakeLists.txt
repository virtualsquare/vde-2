cmake_minimum_required(VERSION 3.10)
project(vde2 
    VERSION 2.3.3 
    LANGUAGES C
)

include(GNUInstallDirs)
include(./Macros.cmake)

add_definitions(-DSYSCONFDIR=\"${CMAKE_INSTALL_SYSCONFDIR}\" -DLOCALSTATEDIR=\"${CMAKE_INSTALL_LOCALSTATEDIR}\")

cm_define_project(
    ${PROJECT_VERSION} 
    ${PROJECT_NAME} 
    ${PROJECT_NAME} 
    "${PROJECT_NAME} ${PROJECT_VERSION}" 
    "info@v2.cs.unibo.it" 
    " " 
    ${PROJECT_NAME}
)

# Options
option(ENABLE_VXLAN "Enable VDE VXLAN" ON)
option(ENABLE_CRYPTCAB "Enable VDE CryptCab" ON)
option(ENABLE_VDE_OVER_NS "Enable VDE over NS" ON)
option(ENABLE_ROUTER "Enable VDE Router" ON)
option(ENABLE_PCAP "Enable pcap support" ON)
option(ENABLE_TUNTAP "Enable tuntap support" ON)
option(ENABLE_EXPERIMENTAL "Enable experimental features" OFF)
option(ENABLE_PROFILE "Enable profiling options" OFF)
set(WITH_CRYPT "wolfssl" CACHE STRING "Choose implementation for cryptcab (wolfssl or mbedtls)")
set(crypt ${WITH_CRYPT})

# Set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

# Check for required libraries
find_library(DL_LIBRARY dl)
find_library(HAVE_WOLFSSL wolfssl)
find_library(PTHREAD_LIBRARY pthread)
find_library(PCAP_LIBRARY pcap)
find_library(HAVE_MBEDTLS mbedtls)

# Check for headers

cm_check_include(arpa/inet.h HAVE_ARPA_INET_H)
cm_check_include(fcntl.h HAVE_FCNTL_H)
cm_check_include(netdb.h HAVE_NETDB_H)
cm_check_include(netinet/in.h HAVE_NETINET_IN_H)
cm_check_include(stddef.h HAVE_STDDEF_H)
cm_check_include(stdint.h HAVE_STDINT_H)
cm_check_include(stdlib.h HAVE_STDLIB_H)
cm_check_include(string.h HAVE_STRING_H)
cm_check_include(strings.h HAVE_STRINGS_H)
cm_check_include(sys/ioctl.h HAVE_SYS_IOCTL_H)
cm_check_include(sys/param.h HAVE_SYS_PARAM_H)
cm_check_include(sys/socket.h HAVE_SYS_SOCKET_H)
cm_check_include(sys/time.h HAVE_SYS_TIME_H)
cm_check_include(syslog.h HAVE_SYSLOG_H)
cm_check_include(termio.h HAVE_TERMIO_H)
cm_check_include(termios.h HAVE_TERMIOS_H)
cm_check_include(unistd.h HAVE_UNISTD_H)
cm_check_include(sys/filio.h HAVE_SYS_FILIO_H)
cm_check_include(sys/bitypes.h HAVE_SYS_BITYPES_H)
cm_check_include(sys/wait.h HAVE_SYS_WAIT_H)
cm_check_include(sys/select.h HAVE_SYS_SELECT_H)
cm_check_include(sys/signal.h HAVE_SYS_SIGNAL_H)
cm_check_include(sys/stropts.h HAVE_SYS_STROPTS_H)
cm_check_include(sys/type32.h HAVE_SYS_TYPE32_H)

cm_check_include(syslimits.h HAVE_SYSLIMITS_H)
cm_check_include(sys/syslimits.h HAVE_SYS_SYSLIMITS_H)
cm_check_include(sysexits.h HAVE_SYSEXITS_H)

cm_check_include(wolfssl/wolfcrypt/chacha.h HAVE_WOLFSSL_CHACHA_H)
cm_check_include(mbedtls/chacha20.h HAVE_MBEDTLS_CHACHA20_H)

# Check for functions
cm_check_function(atexit HAVE_ATEXIT)
cm_check_function(dup2 HAVE_DUP2)
cm_check_function(gethostbyname HAVE_GETHOSTBYNAME)
cm_check_function(gethostname HAVE_GETHOSTNAME)
cm_check_function(gettimeofday HAVE_GETTIMEOFDAY)
cm_check_function(inet_ntoa HAVE_INET_NTOA)
cm_check_function(memmove HAVE_MEMMOVE)
cm_check_function(memset HAVE_MEMSET)
cm_check_function(putenv HAVE_PUTENV)
cm_check_function(select HAVE_SELECT)
cm_check_function(setenv HAVE_SETENV)
cm_check_function(socket HAVE_SOCKET)
cm_check_function(strchr HAVE_STRCHR)
cm_check_function(strdup HAVE_STRDUP)
cm_check_function(strerror HAVE_STRERROR)
cm_check_function(strstr HAVE_STRSTR)

cm_check_function(poll HAVE_POLL)
if(HAVE_POLL)
    if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        message(STATUS "poll present but broken, emulating with select")
        set(EMULATE_DARWIN_POLL TRUE)
        cm_define_var(poll "vde_poll")
        set(HAVE_POLL NO)
    endif()
endif()   

cm_check_function(uname HAVE_UNAME)
cm_check_function(inet_aton HAVE_INET_ATON)
cm_check_function(sprintf HAVE_SNPRINTF)
cm_check_function(readv HAVE_READV)
cm_check_function(random HAVE_RANDOM)
cm_check_function(srandom HAVE_SRANDOM)
cm_check_function(index HAVE_INDEX)
cm_check_function(bcmp HAVE_BCMP)
cm_check_function(drand48 HAVE_DRAND48)
cm_check_function(memmove HAVE_MEMMOVE)
cm_check_function(gethostid HAVE_GETHOSTID)
cm_check_function(revoke HAVE_REVOKE)
cm_check_function(fchmod HAVE_FCHMOD)
cm_check_function(getopt_long_only HAVE_GETOPT_LONG_ONLY)
cm_check_function(funopen HAVE_FUNOPEN)

cm_check_function(open_memstream HAVE_OPEN_MEMSTREAM)
cm_check_function(strndup HAVE_STRNDUP)

cm_check_type_size(char SIZEOF_CHAR)
cm_check_type_size(int SIZEOF_INT)
cm_check_type_size(short SIZEOF_SHORT)
cm_check_type_size("char*" SIZEOF_CHAR_P)

set(MODULES_EXT ${CMAKE_SHARED_LIBRARY_SUFFIX})

cm_define_var(MODULES_EXT \"${CMAKE_SHARED_LIBRARY_SUFFIX}\")

# Platform-specific configurations
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    cm_define_var(VDE_LINUX 1)
elseif(CMAKE_SYSTEM_NAME MATCHES "Android")
    cm_define_var(VDE_BIONIC 1)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    cm_define_var(VDE_DARWIN 1)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    cm_define_var(VDE_FREEBSD 1)
else()
    message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
endif()

if(${crypt} STREQUAL "wolfssl")
  if(HAVE_WOLFSSL AND HAVE_WOLFSSL_CHACHA_H)
    set(CAN_MAKE_CRYPTCAB ON)
  else()
    set(CAN_MAKE_CRYPTCAB OFF)
  endif()
  add_definitions(-DUSE_WOLFSSL=1)
  set(SSL_LIB "wolfssl")
  cm_define_var(HAVE_WOLFSSL 1)
elseif(${crypt} STREQUAL "mbedtls")
  if(HAVE_MBEDTLS AND HAVE_MBEDTLS_CHACHA20_H)
    set(CAN_MAKE_CRYPTCAB ON)
  else()
    set(CAN_MAKE_CRYPTCAB OFF)
  endif()
  add_definitions(-DUSE_WOLFSSL=0)
  cm_define_var(HAVE_MBEDTLS 1)
  set(SSL_LIB "mbedcrypto")
else()
  message(FATAL_ERROR "Unsupported crypt option: ${crypt}. At the moment, only wolfssl and mbedlts are supported. Contributions are appreciated! :-)")
endif()

# Configure features based on options and available libraries
if(CAN_MAKE_CRYPTCAB AND NOT ENABLE_CRYPTCAB)
    set(ENABLE_CRYPTCAB OFF)
elseif(CAN_MAKE_CRYPTCAB AND ENABLE_CRYPTCAB)
    set(ENABLE_CRYPTCAB ON)
elseif(NOT CAN_MAKE_CRYPTCAB AND ENABLE_CRYPTCAB)
    message(WARNING "Cannot make vde_cryptcab: required library (${SSL_LIB}) not found")
    set(ENABLE_CRYPTCAB OFF)
endif()

if(ENABLE_ROUTER AND PTHREAD_LIBRARY)
    set(CAN_MAKE_VDE_ROUTER TRUE)
endif()

if(ENABLE_PCAP AND HAVE_PCAP_OPEN_DEAD)
    set(CAN_MAKE_VDE_PCAP TRUE)
endif()

if(HAVE_SYSEXITS_H)
    set(CAN_MAKE_VDE_OVER_NS TRUE)
else()
    set(CAN_MAKE_VDE_OVER_NS FALSE)
    message(WARNING "Cannot make vde_over_ns: sysexits.h not found")
endif()

if(ENABLE_TUNTAP)
    if(CMAKE_SYSTEM_NAME MATCHES "Linux")
        include(CheckIncludeFile)
        cm_check_include("linux/if_tun.h" HAVE_LINUX_IF_TUN_H)
        if(HAVE_LINUX_IF_TUN_H)
            set(CAN_MAKE_LIBVDETAP YES)
            set(HAVE_TUNTAP YES)
            
        else()
            set(CAN_MAKE_LIBVDETAP NO)
            set(ENABLE_TUNTAP NO)
            message(WARNING "TunTap support is not available on this Linux system.")
        endif()
        

    elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        set(TUNTAP_FILES 
            "/dev/tap0"
            "/Library/Extensions/tap.kext"
            "/System/Library/Extensions/tap.kext"
        )

        foreach(FILE ${TUNTAP_FILES})
            if(EXISTS ${FILE})
                string(MAKE_C_IDENTIFIER "${FILE}" DEFINE_NAME)
                string(TOUPPER "${DEFINE_NAME}" DEFINE_NAME)
                add_definitions(-DHAVE_${DEFINE_NAME}=1)
                set(HAVE_${DEFINE_NAME} YES)
                cm_define_var(HAVE_${DEFINE_NAME} 1)
            endif()
        endforeach()

        if(HAVE__DEV_TAP0_)
            add_definitions(-DHAVE_TUNTAP=1)
            if(NOT HAVE__LIBRARY_EXTENSIONS_TAP_KEXT_ AND NOT HAVE__SYSTEM_LIBRARY_EXTENSIONS_TAP_KEXT_)
                message(WARNING "/dev/tap0 exists, but the kext cannot be found. Let's hope your configuration does work...")
            endif()
        else()
            message(WARNING "You do not have TunTap support. You can get it here: http://tuntaposx.sourceforge.net/")
	    set(ENABLE_TUNTAP OFF)
        endif()

    elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
        include(CheckIncludeFile)
        cm_check_include("net/if_tun.h" HAVE_NET_IF_TUN_H)
        if(HAVE_NET_IF_TUN_H)
            add_definitions(-DHAVE_TUNTAP=1)
        else()
            message(WARNING "TunTap support is not available on this FreeBSD system.")
        endif()
    endif()
endif()

if(VDEPLUG4_LIBRARY)
    message(STATUS "VDE plug4 library found: ${VDEPLUG4_LIBRARY}")
endif()

if(ENABLE_EXPERIMENTAL)
    add_definitions(-DENABLE_EXPERIMENTAL)
endif()

if(ENABLE_PROFILE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
endif()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(include)
add_subdirectory(man)
add_subdirectory(doc)

cm_configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/config.h)

# Install configuration
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/config.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vde2)

# Output configuration summary
message(STATUS "")
message(STATUS "Configure results:")
message(STATUS "")
message(STATUS " VDE VXLAN............... ${ENABLE_VXLAN}")
message(STATUS " VDE CryptCab............ ${ENABLE_CRYPTCAB}")
message(STATUS " VDE Router.............. ${ENABLE_ROUTER}")
message(STATUS " TAP support............. ${ENABLE_TUNTAP}")
message(STATUS " pcap support............ ${ENABLE_PCAP}")
message(STATUS " Experimental features... ${ENABLE_EXPERIMENTAL}")
message(STATUS " Profiling options....... ${ENABLE_PROFILE}")
message(STATUS "")
message(STATUS "")

add_custom_target(uninstall
	"${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
