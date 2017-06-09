#!/usr/bin/python

#python3 setup.py build

import cx_Freeze

executables = [cx_Freeze.Executable("interface.py")]

cx_Freeze.setup(
    name="Web Application Scanner",
    options={"build_exe": {"packages":["pygame"]}},
    executables = executables
    )
