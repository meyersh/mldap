#!/usr/bin/env python

from distutils.core import setup
setup(name='mldap',
      description=
        'A simple interface for manipulating Active Directory using LDAP',
      author='Shaun Meyer',
      author_email='meyersh@morningside.edu',
      url='http://github.com/meyersh/mldap',
      version='1.0',
      py_modules=['mldap'],
      requires=['ldap'],
      )
