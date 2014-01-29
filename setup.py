from distutils.core import setup

setup(
    name='mldap',
    description='A simple interface for manipulating Active Directory with LDAP',
    author='Shaun Meyer',
    author_email='meyersh@morningside.edu',
    url='http://github.com/meyersh/mldap',
    version='2.0.1',
    package_dir={'mldap':'.'},
    packages=['mldap'],
    install_requires=['python-ldap >= 2.3'],
    )
