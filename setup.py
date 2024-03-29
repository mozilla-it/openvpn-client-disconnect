#!/usr/bin/env python
""" Setup script """

import os
import subprocess
from setuptools import setup

NAME = 'openvpn-client-disconnect'
VERSION = '1.4.0'


def git_version():
    """ Return the git revision as a string """
    def _minimal_ext_cmd(cmd):
        # construct minimal environment
        env = {}
        for envvar in ['SYSTEMROOT', 'PATH']:
            val = os.environ.get(envvar)
            if val is not None:
                env[envvar] = val
        # LANGUAGE is used on win32
        env['LANGUAGE'] = 'C'
        env['LANG'] = 'C'
        env['LC_ALL'] = 'C'
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               env=env).communicate()[0]
        return out

    try:
        out = _minimal_ext_cmd(['git', 'rev-parse', 'HEAD'])
        git_revision = out.strip().decode('ascii')
    except OSError:
        git_revision = u"Unknown"

    return git_revision

setup(
    name=NAME,
    packages=['openvpn_client_disconnect'],
    version=VERSION,
    author='Greg Cox',
    author_email='gcox@mozilla.com',
    url="https://github.com/mozilla-it/openvpn-client-disconnect",
    description=("Script to report on disconnecting VPN clients\n" +
                 'This package is built upon commit ' + git_version()),
    entry_points={
        'console_scripts': ['openvpn-client-disconnect=openvpn_client_disconnect:main'],
    },
    long_description=open('README.md').read(),
    license="MPL",
)
