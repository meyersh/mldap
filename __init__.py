#!/usr/bin/env python
"""Mldap2 is a custom AD/LDAP wrapper built using python-ldap. It is
used to simplify programmatic access to the users and groups in a
Windows Server 2003 and Windows Server 2008 Active Directory(tm)
Domain.

"""

__version__ = "2.0.5"
__author__ = "Shaun Meyer"
__date__ = "June, 2009"

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
    """
    Args:
      creds(dict) having these keys:
        * credsfile
        * LDAP_USERNAME
        * LDAP_PASSWORD
        * LDAP_SERVER
        * LDAP_BASE
        * LDAP_USER_BASE
        * LDAP_GROUP_BASE
        * LDAP_DOMAIN

    :returns:
      A connected :class:`adcon.mldap` object.

    """
    return mldap(**creds)
