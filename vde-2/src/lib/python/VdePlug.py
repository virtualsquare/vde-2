#!/usr/bin/python

'''

 LibVdePlug/python wrapper
 Copyright  2010 Daniele Lacamera

 Released under the terms of GNU LGPL v. 2.1
 (see COPYING.libvdeplug in the main project directory)

'''

import vdeplug_python, os, sys, struct
from array import array


class VdeStream:
	def __init__(self, parent, outf, frecv = None, ferr = None):
		self.conn = parent
		self.outf = outf
		self.frecv = frecv
		self.ferr = ferr
		self.conn._streams.append(self)
		if (self.frecv == None):
			self.frecv=self.conn.send
		
	def recv(self, buf):
		(toth, totl) = struct.unpack("BB", buf[0:2])
		tot = (toth << 8) + totl
		buffer = buf[2:]
		if (len(buffer) < tot):
			sys.stderr.write("stream recv: wrong size %d, pkt is %d\n" % (tot, len(buffer)))
			return -1
		elif (len(buffer) > tot):
			self.frecv(buffer[0:tot])
			return self.recv(buffer[tot:]) # Recursion for remaining data
		elif (self.frecv(buffer) < 0):
			return -1
		
	def send(self, buf):
		if self.outf is None:
			return -1 
		lh = (len(buf)>>8) & 0xFF 
		ll = len(buf) & 0xFF
		a = struct.pack("BB", lh, ll)
		self.outf.write(a)
		self.outf.write(buf)
		self.outf.flush()
	
	
	


class VdePlug:

	def __init__(self, sock=None, descr="Python", port=0, group=None, mode=0):
		self._magic = vdeplug_python.open(sock, descr)
		self._ctl = os.fdopen(vdeplug_python.ctlfd(self._magic))
		self._data = os.fdopen(vdeplug_python.datafd(self._magic), 'wb+', os.O_NONBLOCK)
		self._streams = []

	def ctlfd(self):
		return self._ctl

	def datafd(self):
		return self._data

	def send(self, buffer):
		a = array('B', buffer)
		r = self._data.write(a)
		self._data.flush()
		return r

	def recv(self, size):
		return os.read(self._data.fileno(), size)

	def recvfrom_streams(self, buf):
		for s in self._streams:
			s.recv(buf)

	def sendto_streams(self, buf):
		for s in self._streams:
			s.send(buf)

	def close(self):
		vdeplug_python.close(self._magic)
		self._magic = None
		

