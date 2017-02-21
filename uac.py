###############################################################################
# Some UAC (user Account Control) codes
###############################################################################


class uac(object):
    """ An interface to work with userAccountControl flags.

    Example:
      >>> u = ad.getuac('wimpy')
      >>> u.set('ADS_UF_ACCOUNTDISABLE').set('ADS_UF_DONT_EXPIRE_PASSWORD').commit()


    Constants:

    """

    uac_value = 0
    """ Default value (0) """

    ADS_UF_SCRIPT = 0x00000001
    """ The logon script is executed. """

    ADS_UF_ACCOUNTDISABLE = 0x00000002
    """ The user account is disabled. """

    ADS_UF_HOMEDIR_REQUIRED = 0x00000008
    """ The home directory is required. """

    ADS_UF_LOCKOUT = 0x00000010
    """ The account is currently locked out. """

    ADS_UF_PASSWD_NOTREQD = 0x00000020
    """  No password is required.  """

    ADS_UF_PASSWD_CANT_CHANGE = 0x00000040
    """ The user cannot change the password.  Note You cannot assign
    the permission settings of PASSWD_CANT_CHANGE by directly modifying
    the UserAccountControl attribute. For more information and a code
    example that shows how to prevent a user from changing the password,
    see User Cannot Change Password.
    (http://msdn.microsoft.com/en-us/library/aa746508(v=vs.85).aspx ) """

    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
    """ The user can send an encrypted password. """

    ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100
    """ This is an account for users whose primary account is in
    another domain. This account provides user access to this domain,
    but not to any domain that trusts this domain. Also known as a
    local user account. """

    ADS_UF_NORMAL_ACCOUNT = 0x00000200
    """ This is a default account type that represents a typical user. """

    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
    """ This is a permit to trust account for a system domain that trusts
    other domains. """

    ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000
    """ This is a computer account for a computer that is a member of this
    domain. """

    ADS_UF_SERVER_TRUST_ACCOUNT = 0x00002000
    """ This is a computer account for a system backup domain controller that
    is a member of this domain. """

    ADS_UF_DONT_EXPIRE_PASSWD = 0x00010000
    """ The password for this account will never expire. """

    ADS_UF_MNS_LOGON_ACCOUNT = 0x00020000
    """ This is an MNS logon account. """

    ADS_UF_SMARTCARD_REQUIRED = 0x00040000
    """ The user must log on using a smart card. """

    ADS_UF_TRUSTED_FOR_DELEGATION = 0x00080000
    """ The service account (user or computer account), under which a
    service runs, is trusted for Kerberos delegation. Any such service
    can impersonate a client requesting the service. """

    ADS_UF_NOT_DELEGATED = 0x00100000
    """ The security context of the user will not be delegated to a
    service even if the service account is set as trusted for Kerberos
    delegation. """

    ADS_UF_USE_DES_KEY_ONLY = 0x00200000
    """ Restrict this principal to use only Data Encryption Standard
    (DES) encryption types for keys. """

    ADS_UF_DONT_REQUIRE_PREAUTH = 0x00400000
    """ This account does not require Kerberos pre-authentication for
    logon. """

    ADS_UF_PASSWORD_EXPIRED = 0x00800000
    """ The user password has expired. This flag is created by the
    system using data from the Pwd-Last-Set attribute and the domain
    policy. """

    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
    """ The account is enabled for delegation. This is a
    security-sensitive setting; accounts with this option enabled
    should be strictly controlled. This setting enables a service
    running under the account to assume a client identity and
    authenticate as that user to other remote servers on the
    network. """

    @classmethod
    def flags(cls, value):
        """ iterate through flags (using dir()) and return a human-legible
        rendition of account flags.

        >>> someUacObject.flags()
        ['ADS_UF_DONT_EXPIRE_PASSWD', 'ADS_UF_NORMAL_ACCOUNT']
        """
        value = int(value)
        ret = list()
        for flag in dir(uac):
            if 'ADS' in flag:
                if value & cls().__getattribute__(flag):
                    ret.append(flag)

        return ret

    def instance_flags(self):
        """ :return: a list of user-readable flags which are set.

        >>> someUacObject.flags()
        ['ADS_UF_DONT_EXPIRE_PASSWD', 'ADS_UF_NORMAL_ACCOUNT']
        """

        return uac.flags(self.uac_value)

    def set(self, flag):
        """ Set a UAC flag

        Example:
          >>> someUacObject.set(uac.ADS_UF_PASSWORD_EXPIRED).commit()

        :return: Self so that calls may be chained.
        """

        self.uac_value |= int(flag)
        return self

    def unset(self, flag):
        """ Use AND to unset a flag.

        >>> someUacObject.set(uac.ADS_UF_PASSWORD_EXPIRED).commit()

        :return: Self so that calls may be chained.
        """
        self.uac_value &= (~int(flag) & 0xFFFFFFFF)
        return self

    def is_set(self, flag):
        """ Check if a specified flag is set.

        :return: Boolean
        """
        if self.uac_value & int(flag):
            return True
        return False

    def __int__(self):
        return self.uac_value

    def __str__(self):
        return str(self.uac_value)

    def __repr__(self):
        return "<%s object (%s)>" % (self.__class__, str(self.flags()))

    def commit(self):
        """ Commit changes back to the self.objectguid object. """
        #        try:
        self.ad.replace_by_objectguid(self.objectguid,
                                      'userAccountControl',
                                      str(self.uac_value))
        #        except:
        #            raise Exception("No AD data member to commit")

    def __init__(self, value=0, ad_con=None, objectguid=None):
        self.ad = ad_con
        self.objectguid = objectguid
        self.uac_value = int(value)
        self.flags = self.instance_flags
