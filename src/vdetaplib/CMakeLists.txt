if(ENABLE_PROFILE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg --coverage")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg --coverage")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(-DLIBEXECDIR=\"${CMAKE_INSTALL_FULL_LIBEXECDIR}\")

# Define the library
add_library(libvdetap STATIC libvdetap.c)
set_target_properties(libvdetap PROPERTIES
  PREFIX ""
  SUFFIX ".la"
  LINK_FLAGS "-avoid-version -export-dynamic -Wl,-init -Wl,libvdetap_init -Wl,-fini -Wl,libvdetap_fini"
)
target_compile_options(libvdetap PRIVATE -fno-strict-aliasing)

# Define the executable
add_executable(vdetap vdetap.c)
target_link_libraries(vdetap vdecommon vdeplug)

# Install the library
install(TARGETS libvdetap ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/packages)
install(TARGETS vdetap RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_LIBEXECDIR})