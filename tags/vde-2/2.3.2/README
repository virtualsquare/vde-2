VDEv2: Virtual Distributed Ethernet.

(c) 2003/2004/2005/2006 Renzo Davoli
Long long time ago based on uml-router Copyright 2002 Yon Uriarte and Jeff Dike
qemu-vde-HOWTO is (c) by Jim Brown
Notice: Virtual Distributed Ethernet is not related in any way with
www.vde.com ("Verband der Elektrotechnik, Elektronik und Informationstechnik"
i.e. the German "Association for Electrical, Electronic & Information 
Technologies").

Components of the VDE architecture:
- VDE switches: virtual counterpart of ethernet switches.
- VDE cables: virtual counterpart of a crossed-cable used to connect two switches.

- VDE 2 includes:
- switch management both from console and from a "unix socket terminal"
- VLAN 801.1q *almost* compatible
- FSTP (fast spanning tree) already incomplete and currently not tested for 802.1d/w/s
  compatibility. under development. (vde_switch must be compiled with the FSTP flag on)

Using VDE:
- All units connected to the VDE see each other as they were on a real ethernet.
- A real Linux box can be connected to the VDE using a tap interface (TUNTAP)  
  (packets can be further routed using standard linux methods). 
- It is possible to join two VDE switches -- also running on different
  real conputers -- using virtual VDE cables
- UML (user-mode-linux) virtual machines can be connected to the VDE
- MPS (MIPS emulated machines (c) Morsiani/Davoli) can be connected 
to the virtual VDE.

Examples of VDE uses:
- With VDE it is possible to create a virtual network of UML machines running
on several real computer
- VDE can be used to create tunnels (even crossing masquerated networks)
- VDE can provide mobility support. Changing a VDE cable with another does not
affect the communications in place. The new VDE cable can use a completely 
different path on the real net. VDE supports also multiple concurrent VDE cables
between a pair of VDE-switches during the hand-off. This eliminates when possible
hich-ups of communications due to hand-offs.

HOWTO and basic command syntax (for a complete explanation RTM):

vde-switch [ -unix control-socket ] [ -tap tuntap-device ] [ -hub ] [-daemon]
This command creates a VDE switch. 
-unix control-socket
	The control socket is the socket used for local processes to create a new
	connection. The default value is /tmp/vde.ctl.
	User-mode-linux default value is /tmp/uml.ctl, so if you want to use vde 
	with UML you can: (1) use "-unix /tmp/uml.ctl" for vde-switch (2) use 
	"eth0=daemon,,/tmp/vde.ctl" for UML 
-tap tuntap-device
	the vde-switch is connected to the specified tap interface.
	Ususally it is reserved for root as /dev/net/tun is not writable.
	(It is dangerous to have /dev/net/tun writable by ordinary users).
-hub
	the vde-switch works as a hub (all packets are broadcast on all interfaces.
-daemon
	the switch works as a daemon: it runs in background, it uses syslog 
	for error management. 

vde-plug [-p port] [socketname]
A vde-cable is composed by two vde-plug and a "cable". A vde-plug connects its
standard input and output to a switch.
socketname is the control-socket of the switch the plug must be connected to 
(default value /tmp/vde.ctl).
-p port. To use a specific port of the switch. The first available port is
assaigned when not specified. It is possibl eto connect several cables to the
same prot: Cables connected to the same port represent several path
for the same destination.

dpipe cmd1 [arg1] = cmd2 [arg2]
it is the double pipe command (it is here just becouse it is not provided by
shells).
cmd1 and cmd2 are executed, the stdout of cmd1 if pipe connected to the stdin of
cmd2 and viceversa. (the symbol = is intended as a pair of communication pipes
between the two processes.

HOW TO:
- (1) SETUP A DAEMON:
(as root)
# vde_switch -tap tap0 -mod 777 -daemon
# ifconfig tap0 192.168.0.254

if you want to have routing to the Internet you can use standard routing
commands on the host machine e.g.:
# echo "1" > /proc/sys/net/ipv4/ip_forward
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

for ipv6
# echo "1" > /proc/sys/net/ipv6/conf/eth0/forwarding 
# radvd

radvd must be configured to broadcast the correct prefix for the tap0 subnet
	
----- example of /etc/radvd.conf file
interface tap0
{
   AdvSendAdvert on;
   MaxRtrAdvInterval 120;
#put here your prefix.
   prefix 1111:2222:3333:4444::/64 
   { 
	   AdvOnLink on;
	   AdvAutonomous on;
	   AdvRouterAddr on;
							       
   };
};
------ end of example

- (2) SETUP A SECOND DAEMON
(no need for root access)

% vde_switch /tmp/my.ctl

(add - daemon if you want to run it in background)

- (3) CONNECT TWO LOCAL SWITCHES TOGETHER

% dpipe vde_plug = vde_plug /tmp/my.ctl
(or
% dpipe vde_plug /tmp/my.ctl = vde_plug 
)

connects the vde_switch with ctl socket /tmp/vde.ctl with the other using
/tmp/my.ctl.

- (3) CONNECT TWO REMOTE SWITCHES TOGETHER

You need a tool to interconnect stdin stdout of two remote processes.
e.g.

% dpipe vde_plug /tmp/my.ctl = ssh remote_machine vde_plug

connects the vde_switch with ctl socket /tmp/vde.ctl on the remote_machine
with the local switch using /tmp/my.ctl.

It is possible to use other tools in place of ssh like netcat.
In this latter case the communication is not secure.

- (4) CREATION OF TUNNELS.
(it needs kernel support for policy routing)

Setup two daemon as described in (1).
In this example 192.168.0.1 is the tap0 address on the server side.
Route the traffic to the Internet on the tunnel server side.

On the tunnel client side:
	- in the example 100.200.201.202 is the IP address on eth0
	and 100.200.201.254 is the default gateway.
	- create a specific rule for the eth0 routing
		ip rule add from 100.200.201.202 table eth0-table
	(please note that eth0-table must be listed in /etc/iproute2/rt_tables)
		ip route del default via 100.200.201.254
		ip route add default via 100.200.201.254 table eth0-table
	the previous default route will be the def. route just for the
	packets originated with the eth0 inteface address.
	- connect the two vde-switch together:
		dpipe vde-plug = ssh -b 100.200.201.202 server-machine vde-plug
	- setup an appropriate IP address for tap0 interface (or get it by dhcp
	 	if set up on server side). (e.g. 192.168.0.10)
	- use tap0 as the default interface:
		ip route add default via 192.168.0.1

- (5) SUPPORT FOR MOBILITY

Create a tunnel like in 4 using a group number on the vde-cable:
	dpipe vde-plug -g 1 = ssh -b 100.200.201.202 server-machine vde-plug -g 1

Create a second tunnel (say on ppp0 addr. 100.100.101.102 gateway 100.100.101.254)
	# ip rule add from 100.100.101.102 table ppp0-table
	# ip route add default via 100.100.101.254 table ppp0-table

Connect the a second cable using the same group number:
	# dpipe vde-plug -g 1 = ssh -b 100.100.101.102 server-machine vde-plug -g 1
Disconnect the first cable (kill the processes of the first cable)

	All the traffic get rerouted on the new vde-cable (thus to another path
	on the rel network. Connections in place are unaffected by the change.
	Several cables of the same group can be in place during the handoff phase
	but note that this ends up in duplicated packets that can slow down
	the communication.

Please note also that the vde-switches do not manage (yet) the minimum spanning 
tree protocol thus a loop in the topology can lead to inconsistent MAC forward 
tables and to network saturation.

Copyright 2003/2004/2005/2006/2011 Renzo Davoli
This product includes software developed by Danny Gasparovski and Fabrice 
Ballard (slirp support).
Acknowlegments:
Thanks to Marco Giordani, Leonardo Macchia for their useful help for debugging.
Imported code by Danny Gasparovsky, Fabrice Ballard.
Thanks to Giuseppe Della Bianca <bepi@adria.it> for many bug reports, and
patch proposals.
Thanks to Daniel P. Barrange <berrange at redhat dot com> for several patches
and the management of group ownership.
Code organization, bugfixes, autotool support Mattia Belletti.
