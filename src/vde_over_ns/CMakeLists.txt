
# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
set(SOURCES
	vde_over_ns.c
	dns.c
	encode.c
	pstack.c
	queue.c
	util.c
	vde_io.c
	dns.h
	dns_proto.h
	fun.h
	pstack.h
)

# Add executable
add_executable(vde_over_ns ${SOURCES})

# Link libraries
target_link_libraries(vde_over_ns vdecommon vdeplug)

# Enable profiling if requested
if(ENABLE_PROFILE)
	target_compile_options(vde_over_ns PRIVATE -pg --coverage)
	target_link_libraries(vde_over_ns PRIVATE -pg --coverage)
endif()

# Install the executable
install(TARGETS vde_over_ns DESTINATION ${CMAKE_INSTALL_BINDIR})