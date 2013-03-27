from distutils.core import setup

setup(
    name='mldap',
    description=
    'A simple interface for manipulating Active Directory using LDAP',
    author='Shaun Meyer',
    author_email='meyersh@morningside.edu',
    url='http://github.com/meyersh/mldap',
    version='2.0',
    packages=['mldap'],
    requires=['python-ldap'],
    )
