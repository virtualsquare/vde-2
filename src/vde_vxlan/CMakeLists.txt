
set(SOURCES
    log.c
    log.h
    plug.c
    plug.h
    vde_vxlan.c
    vxlan.c
    vxlan.h
    vxlan_hash.c
    vxlan_hash.h
)

include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/vde_switch)

add_executable(vde_vxlan ${SOURCES})

target_link_libraries(vde_vxlan PRIVATE vdecommon vdeplug)

if(ENABLE_PROFILE)
    target_compile_options(vde_vxlan PRIVATE -pg --coverage)
    target_link_options(vde_vxlan PRIVATE -pg --coverage)
endif()

install(TARGETS vde_vxlan DESTINATION ${CMAKE_INSTALL_BINDIR})