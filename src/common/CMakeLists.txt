# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
set(SOURCES
  cmdparse.c
  canonicalize.c
)

#cm_replace_functions(SOURCES strndup open_memstream)

if(NOT HAVE_OPEN_MEMSTREAM)
  set(SOURCES ${SOURCES} open_memstream.c)
endif()

if(NOT HAVE_STRNDUP)
  set(SOURCES ${SOURCES} strndup.c)
endif()

if(EMULATE_DARWIN_POLL)
  set(SOURCES ${SOURCES} poll.c)
endif()

# Add library
add_library(vdecommon STATIC ${SOURCES})

# Profiling and coverage options
if(ENABLE_PROFILE)
  target_compile_options(vdecommon PRIVATE -pg --coverage)
  target_link_options(vdecommon PRIVATE -pg --coverage)
endif()