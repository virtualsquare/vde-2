# Set the include directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Define the source files
set(SOURCES
	rbtree.c
	vde_router.c
	vder_arp.c
	vder_datalink.c
	vder_dhcp.c
	vder_icmp.c
	vder_olsr.c
	vder_packet.c
	vder_queue.c
	vder_udp.c
)

# Define the header files
set(HEADERS
	rbtree.h
	vde_headers.h
	vde_router.h
	vder_arp.h
	vder_datalink.h
	vder_dhcp.h
	vder_icmp.h
	vder_olsr.h
	vder_packet.h
	vder_queue.h
	vder_udp.h
)

# Add the executable
add_executable(vde_router ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(vde_router
	vdecommon
	vdeplug
	pthread
)

# Add profiling flags if enabled
if(ENABLE_PROFILE)
	target_compile_options(vde_router PRIVATE -pg --coverage)
	target_link_options(vde_router PRIVATE -pg --coverage)
endif()

# Install the executable
install(TARGETS vde_router DESTINATION ${CMAKE_INSTALL_BINDIR})