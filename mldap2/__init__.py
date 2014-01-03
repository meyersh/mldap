#!/usr/bin/env python
"""
mldap2 - base module

Custom AD/LDAP Worker Library for Morningside College 2003 AD Domain
Shaun Meyer - June, 2009
"""
__version__ = "2.0.5"

import os
import sys
import warnings
import datetime

from uac import uac
from aduser import ADuser
from adgroup import ADgroup
from adcon import mldap

# Enable all warnings
warnings.simplefilter('default')


class NoSuchObject(Exception):
    """ Provide a custom exception to call when we have no user to
    perform an action upon. """
    pass


def connect(creds):
    """ This class is specifically designed to connect to and interact with
    our Active Directory via LDAP. Return a new instance.

    Named parameters:
      * credsfile
      * LDAP_USERNAME
      * LDAP_PASSWORD
      * LDAP_SERVER
      * LDAP_BASE
      * LDAP_USER_BASE
      * LDAP_GROUP_BASE
      * LDAP_DOMAIN

    """
    return mldap(**creds)
