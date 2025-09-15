# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add subdirectories
add_subdirectory(vdemgmt)

# Enable profiling if requested
if(ENABLE_PROFILE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg --coverage")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg --coverage")
endif()

add_library(vdesnmp SHARED libvdesnmp.c)
target_link_libraries(vdesnmp PRIVATE vdecommon vdemgmt)
set_target_properties(vdesnmp PROPERTIES VERSION 0.0.1 SOVERSION 0)
configure_file(vdesnmp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/vdesnmp.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vdesnmp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS vdesnmp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_library(vdehist SHARED libvdehist.c)
target_link_libraries(vdehist PRIVATE vdecommon)
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  target_compile_options(vdehist PRIVATE -Wall -O2 -g -O2 -fno-common -DPIC)
  target_link_options(vdehist PRIVATE -Wl,-undefined -Wl,dynamic_lookup -Wl,-no_fixup_chains -Wl,-force_load -O2 -g -O2)
endif()
set_target_properties(vdehist PROPERTIES VERSION 0.0.1 SOVERSION 0)
configure_file(vdehist.pc.in ${CMAKE_CURRENT_BINARY_DIR}/vdehist.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vdehist.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS vdehist
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})


# Configure pkg-config files
# Install the libraries

if (NOT WITH_VDEPLUG4)
add_library(vdeplug SHARED libvdeplug.c)
target_link_libraries(vdeplug PRIVATE vdecommon)
set_target_properties(vdeplug PROPERTIES VERSION 3.0.1 SOVERSION 3)
configure_file(vdeplug.pc.in ${CMAKE_CURRENT_BINARY_DIR}/vdeplug.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/vdeplug.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS vdeplug
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
