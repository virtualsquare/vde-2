cmake_minimum_required(VERSION 3.25)

### man pages
file(GLOB VU_MAN_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.[1-8])
foreach(VU_MAN_PATH IN LISTS VU_MAN_PAGES)
	get_filename_component(VU_MANPAGE ${VU_MAN_PATH} NAME)
	string(REGEX REPLACE ".*\\." "" MAN_CHAPTER ${VU_MANPAGE})
	install(FILES ${VU_MAN_PATH} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_CHAPTER})
endforeach(VU_MAN_PATH)
