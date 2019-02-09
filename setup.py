#! /usr/bin/env python

from distutils.core import setup

setup(
    name='mcipc',
    author='Richard Neumann',
    author_email='<mail at richard dash neumann dot de>',
    py_modules=['wgtools'],
    scripts=['files/rconclt', 'files/rconshell', 'files/srvwrap-test'],
    url='https://gitlab.com/coNQP/mcipc',
    license='GPLv3',
    description='A Minecraft server inter-process communication library.')
