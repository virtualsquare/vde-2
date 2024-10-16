# Include directories
include_directories(${CMAKE_SOURCE_DIR})

# Define the headers to be installed
install(FILES libvdesnmp.h libvdemgmt.h DESTINATION include)
install(FILES libvdeplug.h libvdeplug_dyn.h libvdehist.h DESTINATION include)

# Extra distribution files (not directly used in CMake, but listed for reference)
set(EXTRA_DIST
	canonicalize.h
	cmdparse.h
	open_memstream.h
	strndup.h
	vdecommon.h
	vde.h
	vdeplugin.h
	vdepoll.h
)
