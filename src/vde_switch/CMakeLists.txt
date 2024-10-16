

set(SOURCES
	hash.c
	port.c
	vde_switch.c
	sockutils.c
	qtimer.c
	datasock.c
	consmgmt.c
	fstp.c
	packetq.c
	tuntap.c
)

set(HEADERS
	hash.h
	port.h
	switch.h
	sockutils.h
	qtimer.h
	datasock.h
	consmgmt.h
	fstp.h
	packetq.h
	bitarray.h
	tuntap.h
)

add_executable(vde_switch ${SOURCES} ${HEADERS})

target_include_directories(vde_switch PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(vde_switch PRIVATE vdecommon)

target_compile_options(vde_switch PRIVATE -Wall)

if(ENABLE_PROFILE)
	target_compile_options(vde_switch PRIVATE -pg --coverage)
	target_link_options(vde_switch PRIVATE -pg --coverage)
endif()

if(APPLE)
	set(EXP_CFLAGS -dynamic)
else()
	set(EXP_CFLAGS -rdynamic)
endif()

if(ENABLE_EXPERIMENTAL)
	add_subdirectory(plugins)
	target_compile_options(vde_switch PRIVATE ${EXP_CFLAGS})
	target_compile_definitions(vde_switch PRIVATE -DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN -DPLUGINS_DIR="${CMAKE_INSTALL_PREFIX}/lib/plugins")
endif()

install(TARGETS vde_switch DESTINATION ${CMAKE_INSTALL_BINDIR})