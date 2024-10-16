
# Set the include directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Define the libraries
add_library(dump MODULE dump.c)
target_link_libraries(dump vdecommon)

add_library(iplog MODULE iplog.c)
target_link_libraries(iplog vdecommon)

# Handle ENABLE_EXPERIMENTAL flag
if(ENABLE_EXPERIMENTAL)
  add_definitions(-DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN)
endif()

# Handle ENABLE_PCAP flag
if(ENABLE_PCAP)
  add_library(pdump MODULE pdump.c)
  target_link_libraries(pdump vdecommon pcap)
else()
  set(EXTRA_DIST pdump.c)
endif()

# install modules
install(TARGETS dump iplog pdump DESTINATION ${CMAKE_INSTALL_LIBDIR}/modules)