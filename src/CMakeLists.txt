
include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(common)
add_subdirectory(lib)
add_subdirectory(vde_switch)

if(CAN_MAKE_LIBVDETAP)
    add_subdirectory(vdetaplib)
endif()

if (ENABLE_CRYPTCAB)
    add_subdirectory(vde_cryptcab)
endif()

if (CAN_MAKE_VDE_OVER_NS)
    add_subdirectory(vde_over_ns)
endif()

if (CAN_MAKE_VDE_ROUTER)
    add_subdirectory(vde_router)
endif()

if (CAN_MAKE_VDE_PCAP)
    add_executable(vde_pcapplug vde_pcapplug.c)
    target_link_libraries(vde_pcapplug vdeplug pcap)
endif()

if(ENABLE_VXLAN)
    add_subdirectory(vde_vxlan)
endif()

add_executable(vde_plug vde_plug.c)
target_link_libraries(vde_plug vdeplug vdecommon)

add_executable(dpipe dpipe.c)

add_executable(unixcmd unixcmd.c)
target_link_libraries(unixcmd vdecommon)

add_executable(vde_plug2tap vde_plug2tap.c)
target_link_libraries(vde_plug2tap vdeplug vdecommon)

add_executable(vde_autolink vde_autolink.c)
target_link_libraries(vde_autolink vdecommon vdemgmt)

add_executable(wirefilter wirefilter.c)
target_link_libraries(wirefilter vdeplug m vdecommon)

add_executable(vdeterm vdeterm.c)
target_link_libraries(vdeterm vdeplug vdehist vdecommon)

install(TARGETS vde_plug dpipe unixcmd vde_plug2tap vde_autolink wirefilter vdeterm
        DESTINATION ${CMAKE_INSTALL_BINDIR})
