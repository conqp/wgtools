#! /usr/bin/env python
"""Setup script."""


from setuptools import setup


setup(
    name='wgtools',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    author='Richard Neumann',
    author_email='mail@richard-neumann.de',
    python_requires='>=3.8',
    py_modules=['wgtools'],
    url='https://gitlab.com/coNQP/wgtools',
    license='GPLv3',
    description='Python bindings for wireguard-tools.',
    keywords='wireguard python bindings wg tools'
)
