#!/usr/bin/python
from VdePlug import VdePlug, VdeStream
from select import poll
import os, sys
from select import POLLIN, POLLOUT, POLLHUP, POLLERR, POLLNVAL


v = VdePlug(sys.argv[1])
s = VdeStream(v, sys.stdout)
p = poll()
p.register(sys.stdin.fileno(), POLLIN)
p.register(v.datafd().fileno(), POLLIN)
while(True):
	pollret = p.poll()
	for (f,e) in pollret:
		if f == v.datafd().fileno() and (e & POLLIN):
			buffer = v.recv(2000)
			v.sendto_streams(buffer)
		elif f == sys.stdin.fileno() and (e & POLLIN):
			buffer = os.read(f, 2000)
			v.recvfrom_streams(buffer)
