#!/usr/bin/env python
################################################################################
# Shaun Meyer - June, 2009
# Custom AD/LDAP Worker Library for Morningside College 2003 AD Domain
# SRGM Oct, 2011
#   * Continuing code cleanup for GITHUB publication.
# SRGM Aug, 2011
#   * FEATURE: Major cleanup + documenting. 
#   * FEATURE: Added uac object
# SRGM Jul, 2011
#   * FEATURE: Converted from execfile() to ConfigParser() for credsfile
# SRGM Oct, 2010
#   * REWRITE: Adding ADUser and ADGroup objects
# SRGM Jul, 2009
#   * REWRITE: Now Object-Oriented for trialling purposes
# SRGM Jun, 2009 
#   * FEATURE: create() for new accounts
################################################################################

"""
mldap2 - base module
"""

__version__ = "2.0.3"

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


# Helper functions

def deprecated(message=None):
    ''' Call this function with an optional message to raise a warning
    for a depracated function. '''
    if message is None:
        message = "This function is deprecated."
    warnings.warn(message, DeprecationWarning, stacklevel=3)

def flatten(l):
    ''' given a list of no elements, return None.
    given a list of one element, return just the element,
    given a list of more than one element, return the list. '''

    if not l:
        return None

    if isinstance(l, list):
        if len(l) > 1:
           return l
        else:
            return l[0]
        
    return l

def unicodePasswd(str_passwd):
    """ Encode password as unicode for AD."""
    unicode1 = unicode("\"" + str_passwd + "\"", "iso-8859-1")
    unicode2 = unicode1.encode("utf-16-le")
    return unicode2 # Our unicoded password.

###############################################################################
###############################################################################
#
# BEGIN MLDAP OBJECT DEFINITION
#
###############################################################################
###############################################################################



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
