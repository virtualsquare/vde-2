#!/usr/bin/python
from VdePlug import VdePlug
from select import poll
import os, sys, struct
from select import POLLIN, POLLOUT, POLLHUP, POLLERR, POLLNVAL


v = VdePlug(sys.argv[1])
p = poll()
p.register(sys.stdin.fileno(), POLLIN)
p.register(v.datafd().fileno(), POLLIN)
while(True):
	pollret = p.poll()
	for (f,e) in pollret:
		if f == v.datafd().fileno() and (e & POLLIN):
			buffer = v.recv(2000)
			lh = (len(buffer)>>8) & 0xFF 
			ll = len(buffer) & 0xFF
			a = struct.pack("BB", lh, ll)
			sys.stdout.write(a)
			sys.stdout.write(buffer)
			sys.stdout.flush()
		elif f == sys.stdin.fileno() and (e & POLLIN):
			hdr = os.read(f, 2)
			(toth, totl) = struct.unpack("BB", hdr)
			tot = (toth << 8) + totl
			buffer = os.read(f, tot)
			v.send(buffer)


