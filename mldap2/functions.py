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
