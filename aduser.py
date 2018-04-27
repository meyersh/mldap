from uac import uac


class ADuser(object):
    """An Active Directory-backed user-representation object.

    :param username: sAMAccountName of the user.
    :param ad_obj: connected object.
    :type ad_obj: :mod:`mldap2`
    :param attributes: Dictionary to initiate with.

    .. note::

     :func:`__setattr__` is defined, so attribute changes
      will be made live if an ad_obj is provided.

    Example (updating AD with new values):
      >>> u.givenName = "wimpy" 

    Writable attributes are listed in `writable_attributes`.

    """

    attr_map = {
        'firstname': 'givenName',
        'initial': 'initials',
        'lastname': 'sn',
        'idno': 'employeeNumber',
        'email': 'mail',
        'distinguishedName': 'distinguishedName',
        'username': 'sAMAccountName'
        }
    ''' attr_map should be moved. It documents a more general mapping
    to specific AD attributes. '''

    writable_attributes = ['mail',
                           'givenName',
                           'initials',
                           'sn',
                           'employeeNumber',
                           'userPrincipalName',
                           'sAMAccountName'
        ]
    ''' writable_attributes are those that are allowed to be written
    back to AD when using the :func:`commit` function. '''

    def _get_info(self):
        """ Retrieve or initalize this object from the
        :attr:`self.username` attribute. """

        ad_attributes = {'givenName': None,
                         'initials': None,
                         'sn': None,
                         'employeeNumber': None,
                         'mail': None,
                         'memberOf': None,
                         'distinguishedName': None
                         }

        ad_attributes.update(ad.getattr(self.username, ad_attributes.keys()))

        self.firstname = ad_attributes['givenName']
        self.initial = ad_attributes['initials']
        self.lastname = ad_attributes['sn']
        self.idno = ad_attributes['employeeNumber']
        self.email = ad_attributes['mail']
        self.dn = ad_attributes['distinguishedName']
        self.expired = self.adcon.isexpired(self.username)
        self.usertype = self.deduce_usertype_from_dn()

        self.guid = self.adcon.getattr(self.username, 'objectGUID')

        if ad.isdisabled(self.username):
            self.networkstatus = "DISABLED"
        else:
            self.networkstatus = "ENABLED"

    def __init__(self, username, ad_obj=None, attributes=None):
        """
        :param username: sAMAccountName of the user.
        :param ad_obj: connected object.
        :type ad_obj: :mod:`mldap`
        :param attributes: Dictionary to initiate with.

        Example:
          >>> u = ADuser("wimpy", attributes={'mail': 'wimpy@wimpy.org',
                                              'initial': 'w'})

        """
        if ad_obj is None:
            self.adcon = mldap()
        else:
            self.adcon = ad_obj

        self.username = username

        if self.adcon.exists(username) is False:
            self.initiated = False
            return

        #self._get_info()

        if attributes is not None:
            self.__dict__.update(attributes)
        else:
            self.__dict__.update(self.adcon.getattr(username))

        self.initiated = True

    def refresh(self):
        """ Refresh all attributes from Active Directory. """
        self.__init__(self.username)

    def commit(self):
        ''' commit back attribute changes to active directory
        .. note:: deprecated now that __setattr__ has been added. '''
        if (self.initiated is False
            or self.adcon.getuser_by_filter("objectGUID", self.objectGUID)
            is None):
            return

        #This will handle all easy attributes. Even sAMAccountName
        #changes.  if the "new" account already exists, this throws an
        #ldap.ALREADY_EXISTS exception.

        for attr in self.writable_attributes:
            value = getattr(self, attr, None)

            if (value and
                self.adcon.compare_by_objectguid(self.objectGUID, attr, value)
                is False):
                self.adcon.replace_by_objectguid(self.objectGUID, attr, value)

    def update_from(self, other):
        ''' update user attributes from another user type.

        .. note::

          Not implemented.
        '''
        assert isinstance(self, other.__class__)

    def __repr__(self):
        if 'cn' in self.__dict__:
            return "<ADUser: '%(cn)s' (%(sAMAccountName)s)>" % self.__dict__
        else:
            return "<AD User Object(uninitialized)>"

    def __eq__(self, other):
        return self.objectGUID == other.objectGUID

    def __hash__(self):
        return hash(self.objectGUID)

    def __setattr__(self, attr, value):
        """ Sugar over adUserObj.sAMAccountName = "new name" to
        commit it back immediately, if possible, to AD. """

        self.__dict__[attr] = value
        if attr in self.writable_attributes:
            if self.adcon:
                self.adcon.replace_by_objectguid(self.objectGUID,
                                                 attr, value)

    def replace(self, attr, value):
        ''' Replace a given attribute with a new value and commit any
        changes immediately. '''
        if (attr in self.writable_attributes and self.initiated):
            setattr(self, attr, value)
            self.commit()

    def get_uac(self):
        """ Return the UAC object representing this user. """

        return uac(self.userAccountControl,
                   ad_obj=self.adcon, objectguid=self.objectGUID)
