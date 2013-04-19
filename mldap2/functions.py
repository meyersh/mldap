# Helper functions

import datetime

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

def now(dt=datetime.datetime.now()):
    return dt

def epochFromDatetime(dt=datetime.datetime.now()):
    """ Given a datetime object (defaults to now), return the windows
    datetime field used in the accountExpires field. 

    The date when the account expires. This value represents the
    number of 100-nanosecond intervals since January 1, 1601 (UTC). A
    value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates
    that the account never expires.
    """

    winnt_epoch = datetime.datetime(1601, 1, 1, 0, 0)
    
    never_expires = 9223372036854775807L

    diff = dt - winnt_epoch

    total_seconds = diff.days * 86400 + diff.seconds

    return int(total_seconds*10000000)

def epochToDatetime(epoch):
    """ Given the windows datetime field used in the accountExpires
    field, return a datetime object representing it.

    The date when the account expires. This value represents the
    number of 100-nanosecond intervals since January 1, 1601 (UTC). A
    value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates
    that the account never expires.
    """
    winnt_epoch = datetime.datetime(1601, 1, 1, 0, 0)
    
    return winnt_epoch + datetime.timedelta(microseconds=int(epoch)/10)

    

# All expired users expired before datetime object `d`
# [x['sAMAccountName'] for x in ad.getattrs_by_filter('accountExpires', mldap2.functions.epochFromDatetime(d), compare='<=', attrlist=['sAMAccountName'], addt_filter="(accountExpires>=1)(accountExpires<=9223372036854775806)")]
