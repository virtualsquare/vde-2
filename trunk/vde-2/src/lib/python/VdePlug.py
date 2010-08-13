#!/usr/bin/python

'''

 LibVdePlug/python wrapper
 Copyright  2010 Daniele Lacamera

 Released under the terms of GNU GPL v.2

'''

import vdeplug_python
import os
from array import array


class VdePlug:

	def __init__(self, sock=None, descr="Python", port=0, group=None, mode=0):
		self._magic = vdeplug_python.open(sock, descr)

		self._ctl = os.fdopen(vdeplug_python.ctlfd(self._magic))
		self._data = os.fdopen(vdeplug_python.datafd(self._magic), 'wb+', os.O_NONBLOCK)

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
	
	def close(self):
		vdeplug_python.close(self._magic)
		self._magic = None
		
		
	

