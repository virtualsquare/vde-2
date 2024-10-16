# Define the files to be distributed
set(EXTRA_DIST
	libvdemgmt/asyncrecv.rc
	libvdemgmt/sendcmd.rc
	libvdemgmt/openmachine.rc
	libvdemgmt/closemachine.rc
	vde_autolink-HOWTO
	vdeqemu-HOWTO
	vdecmd
	freebsd_tap-HOWTO
	bochs/eth_vde.cc
	bochs/eth.cc.diff
	README.UML
	README.bochs
	README.qemu
	README.slirpvde
	README.vde_over_ns
	README.VirtualBox
	VirtualBox-3.1.6_OSE_VDE.patch
)

# Install the files
install(FILES ${EXTRA_DIST} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/vde2)

# Define the directories for installation
set(vdecmddir ${CMAKE_INSTALL_SYSCONFDIR}/vde2)
set(libvdemgmtdir ${CMAKE_INSTALL_SYSCONFDIR}/vde2/libvdemgmt)

# Install the vdecmd file
install(FILES vdecmd DESTINATION ${vdecmddir})

# Install the libvdemgmt files
install(FILES
	libvdemgmt/asyncrecv.rc
	libvdemgmt/closemachine.rc
	libvdemgmt/openmachine.rc
	libvdemgmt/sendcmd.rc
	DESTINATION ${libvdemgmtdir}
)