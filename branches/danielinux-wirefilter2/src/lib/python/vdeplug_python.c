/*
 * LibVdePlug/python wrapper
 * Copyright © 2010 Daniele Lacamera
 *
 * Released under the terms of GNU LGPL v. 2.1
 * (see COPYING.libvdeplug in the main project directory)
 *
 */
#include "Python.h"
#include <stdio.h>
#include "libvdeplug.h"


static PyObject *vdeplug_open(PyObject *self, PyObject *args)
{
	struct vde_open_args vde_args = {0,NULL,0};
	char *vde_sock = NULL, *vde_descr = NULL;
	VDECONN *ret;
	int e;

	if (!PyArg_ParseTuple(args, "ss|isi", &vde_sock, &vde_descr, &vde_args.port, &vde_args.group, &vde_args.mode))
		goto failure; 

	ret = vde_open_real(vde_sock, vde_descr, 1, &vde_args);
	e = errno;
	if (!ret)
		goto failure;
	else
		return PyLong_FromUnsignedLong((unsigned long) ret);

	
failure:
	return PyErr_SetFromErrno(PyExc_RuntimeError);
}

static PyObject *vdeplug_ctlfd(PyObject *self, PyObject *args)
{
	VDECONN *conn;
	unsigned long vde_magic = 0;

	if (!PyArg_ParseTuple(args, "k", &vde_magic))
		goto failure; 
	conn = (VDECONN *) vde_magic;

	if (!conn)
		goto failure;

	return Py_BuildValue("i", vde_ctlfd(conn));
	
failure:
	return PyErr_SetFromErrno(PyExc_RuntimeError);
}

static PyObject *vdeplug_datafd(PyObject *self, PyObject *args)
{
	VDECONN *conn;
	unsigned long vde_magic = 0;

	if (!PyArg_ParseTuple(args, "k", &vde_magic))
		goto failure; 
	conn = (VDECONN *) vde_magic;

	if (!conn)
		goto failure;

	return Py_BuildValue("i", vde_datafd(conn));
	
failure:
	return PyErr_SetFromErrno(PyExc_RuntimeError);
}

static PyObject *vdeplug_close(PyObject *self, PyObject *args)
{
	VDECONN *conn;
	unsigned long vde_magic = 0;

	if (!PyArg_ParseTuple(args, "k", &vde_magic))
		goto failure; 
	conn = (VDECONN *) vde_magic;

	if (!conn)
		goto failure;

	return Py_BuildValue("i", vde_close(conn));
	
failure:
	return PyErr_SetFromErrno(PyExc_RuntimeError);
}



static PyMethodDef vdeplug_methods[] = {
    {"open",  vdeplug_open, METH_VARARGS},
    {"ctlfd",  vdeplug_ctlfd, METH_VARARGS},
    {"datafd",  vdeplug_datafd, METH_VARARGS},
    {"close",  vdeplug_close, METH_VARARGS},
    {NULL,      NULL}        /* Sentinel */
};

void initvdeplug_python(void)
{
	(void) Py_InitModule("vdeplug_python", vdeplug_methods);
//	PyErr_SetString(PyExc_RuntimeError,"vdeplug error");
}
