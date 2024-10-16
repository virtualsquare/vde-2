# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
set(SOURCES
  crc32.c
  cryptcab.c
  vde_cryptcab_server.c
  vde_cryptcab_client.c
)

# Add executable
add_executable(vde_cryptcab ${SOURCES})

# Link libraries
target_link_libraries(vde_cryptcab
  vdecommon
  ${SSL_LIB}
  vdeplug
)

# Compiler flags
target_compile_options(vde_cryptcab PRIVATE -fno-strict-aliasing -DHAVE_CHACHA -DTFM_TIMING_RESISTANT -DNO_ECC -DNO_RSA)

# Profile flags
if(ENABLE_PROFILE)
  target_compile_options(vde_cryptcab PRIVATE -pg --coverage)
  target_link_libraries(vde_cryptcab PRIVATE -pg --coverage)
endif()

# Install the executable
install(TARGETS vde_cryptcab DESTINATION ${CMAKE_INSTALL_BINDIR})