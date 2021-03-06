import ldap
import ldap.filter
#from ldap.controls import SimplePagedResultsControl

from uac import uac
from aduser import ADuser
from adgroup import ADgroup

from functions import unicodePasswd
from functions import flatten
from functions import epochToDatetime

import datetime
import warnings


class NoSuchObject(Exception):
    pass


class mldap:
    """ This class is specifically designed to connect to and interact with
    our Active Directory via :mod:`ldap`.

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

    def __init__(self, **args):
        """
        :type creds: Dictionary
        :param dict creds: Dictionary which optionally contains LDAP_USERNAME,
        LDAP_PASSWORD, or LDAP_SERVER keys to override what is loaded from
        the credsfile variable.
        """

        self.__dict__.update(args)

        # Warn for missing keys in the configuration.
        for element in ('LDAP_USERNAME', 'LDAP_PASSWORD',
                        'LDAP_SERVER', 'LDAP_BASE',
                        'LDAP_USER_BASE', 'LDAP_GROUP_BASE', 'LDAP_DOMAIN'):
            if element not in args:
                warnings.warn(("Missing parameter '%s' in mldap object "
                               "instanciation.") % element)

        self.connect()

    def alive(self):
        """ A quick test to verify if a connection is still active. """
        try:
            self.exists(self.LDAP_USERNAME)
            return True
        except ldap.LDAPError, e:
            """ e will be "LDAP connection invalid" though I'm avoiding
            doing a string compare on this fact. """
            return False

    def connect(self):
        """ Try to build a connection.

        .. note::

          This shouldn't (but does) call :func:`sys.exit` for
          :exc:`ldap.INVALID_CREDENTIALS` and :exc:`ldap.SERVER_DOWN`
          exceptions!

        """
        try:
            # build a client
            self.ldap_client = ldap.initialize(self.LDAP_SERVER)
            # I added this from the internet to fix this new problem
            # where our bind isn't working?? seemed to fix it
            self.ldap_client.set_option(ldap.OPT_REFERRALS, False)

            # perform a synchronous bind
            self.ldap_client.simple_bind_s(
                self.LDAP_USERNAME, self.LDAP_PASSWORD)

        except ldap.INVALID_CREDENTIALS, e:
            print "Invalid credentials: ", e
            sys.exit()
        except ldap.SERVER_DOWN, e:
            print "Your server (%s) appears to be down." % self.LDAP_SERVER
            for error in e:
                print "  %(info)s\n  %(desc)s" % (error)
            sys.exit()

        return self.ldap_client

    # TODO: Remove this function!
    # All code using it can be done with getattrs_by_filter("employeeNumber").
    def checkidno(self, idno):
        """ Taking an IDNO as only argument, does a search in the
        employeeNumber LDAP field for this value.

        .. deprecated:: 2.0
           Use :func:`getattr_by_filter` instead.

        :param idno: string containing the users 7-digit ID.NO

        :return:
            sAMAccountName or None
        """
        searchpath = self.LDAP_USER_BASE
        search = '(&(employeeNumber=%s))' % idno
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName', 'sAMAccountName'])

        if not len(result):
            return None
        else:
            if 'sAMAccountName' in result[0][1]:
                return result[0][1]['sAMAccountName'][0]

    def exists(self, samaccountname):
        """Check if an account exists based on the presence of a
        sAMAccountName

        :return: bool

        """
        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(samaccountname)
        result = self.ldap_client.search_s(
                searchpath,
                ldap.SCOPE_SUBTREE,
                search,
                ['sAMAccountName'])
        if "sAMAccountName" not in result[0][1]:
            return False
        else:
            return True

#
# Peruse a given base OU and return all sAMAccountNames...
#

    def listou(self,
               base=None,
               objectType='sAMAccountName',
               pageSize=1000):
        """Return a list all sAMAccountNames in a given OU

        .. todo:
           Update this to work with python-ldap-2.4+ (they changed the
          api.)

        """
        if base is None:
            base = self.LDAP_USER_BASE
        search = '%s=*' % (objectType)

        res = self.getattrs_by_filter(
            objectType,
            "*",
            attrlist=[objectType],
            base=base,
            pageSize=pageSize)

        return [x['sAMAccountName'] for x in res]

#
# Replace/Set the value of a given attribute for the specified user.
#

    def replace(self, samaccountname, attribute, value):
       """Replace/Set/Clear the value of a given attribute for the specified
       user. """

       # Tuple: (mod_op, mod_type, mod_vals) where
       # mod_op is one of ldap.MOD_ADD, ldap.MOD_DELETE, ldap.MOD_REPLACE
       # mod_type is the attribute name
       # mod_vals is a string value, or list of string values to
       #   add/delete/replace. For the delete operation, mod_vals may be
       #   None indicating that ALL values are to be deleted.

       if not value: # Deleting an old value.
           mod_list = [(ldap.MOD_DELETE,
                        attribute,
                        self.getattr(samaccountname, attribute))]
       else: # Setting the value
           mod_list = [( ldap.MOD_REPLACE, attribute, value )]

       dn=self.get_dn_from_sn(samaccountname)
       if dn is None:
           raise NoSuchObject(samaccountname)
       self.ldap_client.modify_s(dn, mod_list)


    def replace_by_objectguid(self, objectGUID, attribute, value):
       """ Replace/Set the value of a given attribute for the
       specified user. """
       mod_attrs = [( ldap.MOD_REPLACE, attribute, value )]
       dn=self.get_dn_from_objectguid(objectGUID)
       if dn is None:
           raise NoSuchObject(objectGUID)
       self.ldap_client.modify_s(dn, mod_attrs)



    def delete_user(self, samaccountname):
        """ Attempt to delete a given dn by referencing samaccountname. """
        if (self.exists(samaccountname)):
            dn = self.get_dn_from_sn(samaccountname)
            self.ldap_client.delete(dn)

#
# Create a new account with specified attributes set.
# All 'attributes' are expected to be LDAP attributes
# except for 'password' which is properly converted
# for unicodePwd.
#

    def create(self, samaccountname, cn, path, CONSTattributes={}):
        """ Create a new account with the specified attributes set.
        All 'attributes' are expected to be LDAP attributes except
        for attributes['password'] which is properly converted for
        AD's unicodePwd field.

        :type samaccountname: str
        :param samaccountname: Username to create

        :type cn: str
        :param cn: CN of new account (only the CN=(whatever))

        :type path: str
        :param path: ldap path of OU for new account

        :type CONSTattributes: dict
        :param CONSTattributes: A dict of LDAP attributes for the new account.

        """

        # Dictionaries are passed by reference, I do not want to
        # modify it outside of function scope.
        # SRGM - Jun 1, 2010
        attributes = dict(CONSTattributes)

        if not self.exists(samaccountname):
            dn = "CN=%s,%s" % (cn, path)

            # The default password is 'changeme'
            if 'password' not in attributes:
                attributes['password'] = 'changeme'

            # Encode password as unicode for AD.
            attributes['password'] = unicodePasswd(attributes['password'])

            # TODO: Make this more general
            userprincipalname = "%s@%s" % (samaccountname, self.LDAP_DOMAIN)

            add_record = [
                    ('objectclass', 'user'),
                    ('userPrincipalName', userprincipalname),
                    ('samaccountname', samaccountname),
                    ('cn', cn),
                    ('unicodePwd', attributes['password']),
                    # This will cause the account to be enabled/"normal"
                    ('userAccountControl', '512'),
                    #('ou', path)
                    ]

            # Any additional attributes?
            for i in attributes:
                if i != 'password':
                    entry = (i, attributes[i])
                    add_record.append(entry)

            try:
                self.ldap_client.add_s(dn, add_record)
            except ldap.CONSTRAINT_VIOLATION, info:
                print info
        else:
            print "sAMAccountName '%s' already exists!" % samaccountname

    def create_group(self, groupname, path, members=[]):
        """ Create a new group with the specified members.

        :type groupname: str
        :param groupname: Group name to create

        :type path: str
        :param path: base CN of new group

        :type members: list
        :param members: A list of sAMAccountName's to add to this new group.

        """

        if self.exists(groupname):
            return False  # The group already exists.

        # Try to massage the members list into a list of DN's
        group_members = list()
        if members:
            for m in list(set(members)):  # no duplicates
                if ad.exists(m):
                    group_members.append(ad.get_dn_from_sn(m))

        dn = "CN=%s,%s" % (groupname, path)

        add_record = [
            ('objectclass', ['top', 'group']),
            ('samaccountname', groupname),
            ('cn', groupname)
            ]

        try:
            self.ldap_client.add_s(dn, add_record)
            for m in group_members:
                self.add_to_group(m, groupname)
        except ldap.CONSTRAINT_VIOLATION, info:
            print info

    def try_member_search(self, sAMAccountName):
        searchpath = ('cn=group,dc=base')

        search = '(member=%s)' % self.get_dn_from_sn(sAMAccountName)

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        if not len(result):
            return 0
        else:
            return result[0][0]  # We need a more reliable way to get
                                 # this info.

#
# Return a DN for a given SN (sAMAccountName)
#

    def get_dn_from_sn(self, samaccountname):
        """ Return a DN for a given sAMAccountName """
        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(samaccountname)
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        if not len(result):
            return 0
        else:
            return result[0][0]  # We need a more reliable way to get
                                 # this info.

    def get_dn_from_objectguid(self, objectguid):
        """ Return a DN for a given sAMAccountName """
        searchpath = self.LDAP_BASE
        search = 'objectGUID=%s' % ldap.filter.escape_filter_chars(
            str(objectguid))
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        if not len(result):
            return 0
        else:
            return result[0][0]  # We need a more reliable way to get
                                 # this info.

    def get_sn_from_dn(self, DN):
        """ Return the sAMAccountName from DN """
        search = DN

        result = self.ldap_client.search_s(
            search,
            ldap.SCOPE_SUBTREE,
            attrlist=['sAMAccountName'])

        if not len(result):
            return 0
        else:
            return result[0][1]['sAMAccountName'][0]

    def replace_by_idno(self, idno, attribute, value):
        """Replace/Set the value of a given attribute for the specified user
        (by IDNO)."""
        mod_attrs = [(ldap.MOD_REPLACE, attribute, value)]
        dn = self.get_dn_from_idno(idno)
        self.ldap_client.modify_s(dn, mod_attrs)

    def get_dn_from_idno(self, idno):
        """ Return a DN for a given ID.NO """
        searchpath = self.LDAP_USER_BASE
        search = 'employeeNumber=' + str(idno)
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        # Deal with NO results:
        if not len(result):
            return 0

        # Deal with Multiple results (Should not happen):
        assert len(result) == 1

        return result[0][0]  # Return the first DN from our results
                             # (no way we got two, right??)

    def resetpw(self, sAMAccountName, newpass):
        """Wraps around L{self.replace()} to reset a given
        password.

        .. note:: This attempts the administrative reset using the
          user this instance used to bind, make sure that it has the
          proper AD permissions.

        """

        self.replace(sAMAccountName,
                     'unicodePwd',
                     unicodePasswd(newpass))

    def resetpw_by_objectguid(self, objectGUID, newpass):
        """ Perform an administrative password reset. To perform this
        reset, the account that was used to bind to ldap must have
        permissions in AD to reset the password belonging to
        `objectGUID` object. """

        self.replace_by_objectguid(objectGUID,
                                   'unicodePwd',
                                   unicodePasswd(newpass))

###############################################################################
# A few group functions
###############################################################################

    def add_to_multivalued(self, objectguid, attribute, value):
        """Add a given `value` to the multivalued `attribute` on the object
        identified by `objectguid`. 

        Returns: None
        """
        if type(value) is not type(list()):
            value = [value]

        try:
            self.ldap_client.modify_s(self.get_dn_from_objectguid(objectguid),
                                      [(ldap.MOD_ADD, attribute, value)])
        except ldap.ALREADY_EXISTS:
            return  # entry is already there.

    def remove_from_multivalued(self, objectguid, attribute, value):
        if type(value) is not type(list()):
            value = [value]

        try:
            self.ldap_client.modify_s(self.get_dn_from_objectguid(objectguid),
                                      [(ldap.MOD_DELETE, attribute, value)])
        except ldap.NO_SUCH_ATTRIBUTE:
            return  # No such attribute to remove.

#
# Adds a user to a given group.
#

    def add_to_group(self, sAMAccountName, groupCN):
        """ Add a user to a given group 

        Returns: 0 (success), 1 (exception :mod:ldap.ALREADY_EXISTS)
        """
        dn = self.get_dn_from_sn(sAMAccountName)
        group = self.get_dn_from_sn(groupCN)
        try:
            self.ldap_client.modify_s(group, [(ldap.MOD_ADD, 'member', [dn])])
            return 0
        except ldap.ALREADY_EXISTS:
            print "Cannot add %s to group %s: user is already a member." % (
                sAMAccountName,
                groupCN)
            return 1

#
## Remove a user from a given group.
#

    def remove_from_group(self, sAMAccountName, groupCN):
        """ Remove a user from a given group. """
        dn = self.get_dn_from_sn(sAMAccountName)
        group = self.get_dn_from_sn(groupCN)

        try:
            self.ldap_client.modify_s(group,
                                      [(ldap.MOD_DELETE, 'member', [dn])])
            return 0
        except:
            return 1

#
# Returns a list of group members.
#

    def group(self, groupCN):
        """ Return the list of sAMAccountName's from a given groups' members field. """
        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(groupCN)
        attrs = ['member', 'objectClass']

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            attrs)
        #members=result[0][1]['member']
        members = result

        return members

    def bgroup(self, group):
        """Return all attributes for all users who are memberOf= a given
        group"""
        filter = "(&(memberOf=%s))" % self.get_dn_from_sn(group)
        i = self.ldap_client.search(self.LDAP_BASE,
                                  ldap.SCOPE_SUBTREE,
                                  filterstr=filter)
        return self.ldap_client.result(i)[1]

    def unpack_attributes(self, result_set):
        r = result_set[1]  # the actual results.
        unpacked_set = dict()
        for attr in r:
            if len(r[attr]) == 0:
                unpacked_set[attr] = None
            elif len(r[attr]) == 1:
                unpacked_set[attr] = r[attr][0]
            elif len(r[attr]) > 1:
                unpacked_set[attr] = r[attr]
        return unpacked_set

    def checkuser(self, samaccountname):
        """
        Returns a given set of attributes for an SN.

        .. deprecated:: 2.0
           Use :func:`getattr` instead.
        """

        searchpath = self.LDAP_BASE
        # This should probably look like...
        # (&(givenName=%s)(sn=%s))
        # Search for first & last name exactly:
        #search = '(&(givenName=%s)(sn=%s))' % (first, last)
        # Search for first + last name:
        search = 'samaccountname=' + str(samaccountname)
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['givenName', 'sn', 'initials', 'last', 'mail', 'cn'])
        if not len(result[0]):
            return 0
        else:
            return result[0][1]
#
# Verify a value (ldap compare)
#
# exception: ldap.NO_SUCH_ATTRIBUTE

    def compare_by_objectguid(self, objectguid, attr, value):
        """Verify that an AD object has attr set to value (using ldap
        compare).

        Returns: True if the `value` is a match.

        Raises: :mod:`ldap.NO_SUCH_ATTRIBUTE`

        """

        if not value:
            return (self.getattr_by_filter('objectGUID', objectguid, attr)
                    is None)

        dn = self.get_dn_from_objectguid(objectguid)
        try:
            return self.ldap_client.compare_s(dn, attr, value) == 1
        except ldap.NO_SUCH_ATTRIBUTE:
            return False

    def compare(self, samaccountname, attr, value):
        """ Perform an ldap compare operation on an AD object.

        :return: Bool (True for match)

        :raises: :exc:`ldap.NO_SUCH_ATTRIBUTE`"""

        return self.compare_by_objectguid(
            self.getattr(samaccountname, 'objectGUID'), attr, value)

#
# Return a multivalued attribute from AD
#
    def getmattr(self, samaccountname, attr="*"):
        """ Return a multiple, multivalued, attributes from AD.

        When working with results from LDAP the scheme is as follows:

        C{results[r][n]{attr}[values]}

        Where:
            - C{r = result number}
            - C{n[0] = dn of result}
            - C{n[1] = search attributes}
            - C{{attr} = dictionary of attribute:[values]}
            - C{[values] = list of values (always in list form)}
        """

        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(samaccountname)

        # Determine if attr is str or list type:
        if type(attr).__name__ == 'str':
            attrs = [attr]
        elif type(attr).__name__ == 'list':
            attrs = attr

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            attrs)

        # result[r][n]{attr}[A]
        # where:
        # r = result number
        # n = 0 for result DN, 1 for attributes
        # (if n=1): {attr} = dictionary of attributes
        # A = list of attribute values

        return result

#
# Lookup attributes on a given samaccountname
# if not specified, return all attributes.
# getattr(samaccountname, [attr1, attr2, ...])
# getattr(samaccountname)
#
    def getattr_old(self, samaccountname, attr="*"):
        """ Lookup attributes on a given sAMAccountName. If
        not specified, return all attributes.

        Usage:
          getattr(sAMAccountName, [attr1, attr2, ...])
          getattr(samaccountname)

        .. deprecated:: 2.0
           Use :func:`getattr` instead.
        """

        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(samaccountname)

        # Determine if attr is str or list type:
        if type(attr).__name__ == 'str':
            attrs = [attr]
        elif type(attr).__name__ == 'list':
            attrs = attr

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            attrs)

        attributes = result[0][1]  # Because they nest it so darn deep!

        # This reorganizes the results. Normally the ldap module
        # allows you to get many accounts' worth of results back in
        # one go so we end up with a dictionary of lists. Ugh, we're
        # only getting one back here so this cleans up a lot. If we
        # passed multiple attributes we get a dict back if we passed
        # one we get a list with one item...

        if self.exists(samaccountname):
            result = {}
            for i in attributes:
                result[i] = attributes[i][0]

            else:
                if len(result) > 1:
                    return result
                else:

                    # BUG: If attr=[] is a list of two items and one does not
                    # return anything or is incorrect you will get an exception
                    # TypeError.

                    try:
                        return result[attr]
                    except KeyError:
                        return None
        else:
            return 0

    def getattr(self, samaccountname, attr="*"):
        """ Lookup attributes on a given sAMAccountName. If
        not specified, return all attributes.

        :param attr: String containing one LDAP attribute, a list of
            LDAP attributes, or a string containing '*' to return all
            attributes.

        :return: Requested attr. If Multiple attributes are requested,
            returns a a dictionary with attr keys.

        Usage:
          >>> getattr(sAMAccountName, [attr1, attr2, ...])
          >>> getattr(samaccountname)

        Examples:
          >>> mldapObj.getattr("wimpy", "sAMAccountName")
          'wimpy'

          >>> mldapObj.getattr("wimpy")['mail']
          'wimpy@wimpy.org'

          >>> mldapObj.getattr("wimpy", ['sAMAccountName', 'mail'])
          {'mail': 'wimpy@wimpy.org', 'sAMAccountName': 'wimpy'}

          """

        if not self.exists(samaccountname):
            return None

        searchpath = self.LDAP_BASE
        search = 'samaccountname=' + str(samaccountname)

        if isinstance(attr, str):
            attrs = [attr]
        else:
            attrs = list(attr)

        result = self.ldap_client.search_s(
            searchpath, ldap.SCOPE_SUBTREE, search, attrs)

        attributes = result[0][1]  # Because they nest it so darn deep!

        # This reorganizes the results. Normally the ldap module
        # allows you to get many accounts' worth of results back in
        # one go so we end up with a dictionary of lists. Ugh, we're
        # only requesting one back here so this cleans up a lot. If we
        # passed multiple attributes we get a dict back if we passed
        # one we get a list with one item...

        result = dict()
        for i in attributes:
            if not attributes[i]:
                result[i] = None
                continue

            # Unpack a single item into a string
            if len(attributes[i]) == 1:
                result[i] = attributes[i][0]

            else:  # Otherwise, return the multi-value entry as a list.
                result[i] = attributes[i]

        if (attr == "*" or len(attrs) > 1):
            return result
        else:
            return result.get(attrs[0])

    def getuac(self, samaccountname):
        """ Retrieve the userAccountControl field for a given user.
        >>> ad.getuac('shaunt').flags()
        ['ADS_UF_NORMAL_ACCOUNT']

        >>> ad.getuac('shaunt')
        <<class 'mldap.uac'> object (['ADS_UF_NORMAL_ACCOUNT'])>

        >>> ad.getuac('wimpy').set(uac.ADS_UF_PASSWORD_EXPIRED).commit()

        :return: a :class:`uac.uac` object derived from these flags.
        """
        userAccountControl_flags = int(
            self.getattr(samaccountname, 'userAccountControl'))

        return uac(value=userAccountControl_flags,
                   ad_con=self,
                   objectguid=self.getattr(samaccountname, 'objectGUID'))

    def setuac(self, samaccountname, new_uac):
        """ Set the uac field for a given user.

        :param new_uac: The decimal representation of the
          userAccountControl field (actually, any input is ok as long as
          it converts properly with str() which at this time means
          string, uac object, or int. This means '512', 512, uac(512)
          are all acceptable. """
        self.replace(samaccountname, 'userAccountControl', str(new_uac))

    def ismember(self, samaccountname, group):
        '''Check if a given samaccountname is a member of a given group.'''
        if not group or not self.exists(group):
            return False

        memberOf = self.getattr(samaccountname, 'memberOf')

        return (memberOf is not None
                and self.get_dn_from_sn(group) in memberOf)

    def isdisabled(self, samaccountname):
        """ Is a given SN disabled? """
        return self.getuac(samaccountname).is_set(
            uac.ADS_UF_ACCOUNTDISABLE)

    def isexpired(self, samaccountname):
        """ Is a given sAMAccountName expired?

        accountExpires is the number of ticks (100n/s [.0000001s])
        since 12:00AM Jan 1, 1601. [#thanksMS]_ Additionally, it's in UTC

        If a user object in Active Directory has never had an
        expiration date, the accountExpires attribute is set to a huge
        number. The actual value is 2^63 - 1, or
        9,223,372,036,854,775,807.

        """

        winnt_time = int(self.getattr(samaccountname, 'accountExpires'))

        never_expires = 9223372036854775807L

        if winnt_time == never_expires or winnt_time == 0:
            return False

        return datetime.datetime.now() > epochToDatetime(winnt_time)


    def islocked(self, samaccountname):
        """Is a given account locked?

        MSDN has this to say about lockoutTime:

        The date and time (UTC) that this account was locked out. This
        value is stored as a large integer that represents the number
        of 100-nanosecond intervals since January 1, 1601 (UTC). A
        value of zero means that the account is not currently locked
        out.

        However, further down the MSDN page says:

        This attribute value is only reset when the account is logged
        onto successfully. This means that this value may be non zero,
        yet the account is not locked out. To accurately determine if
        the account is locked out, you must add the Lockout-Duration
        to this time and compare the result to the current time,
        accounting for local time zones and daylight savings time.

        """
        if self.getattr(samaccountname, 'lockoutTime') is None:
            return False

        lockoutTime = int(self.getattr(samaccountname, 'lockoutTime'))
        if lockoutTime == 0:
            return False

        lockoutDuration = int(self.getattr(samaccountname, 'lockoutDuration') or 0)

        validAfter = epochToDatetime(lockoutTime + lockoutDuration)
        if validAfter < datetime.datetime.now():
            return False

        # Otherwise, the account is locked.
        return True

#
# Search AD for a given first and last name.
#

    def search(self, first, last):
        """ 

        .. note:: This function is Deprecated. 
        Use :func:`adcon.getattr_by_filter('anr', 'first last', 'sAMAccountName')` instead. 
        """
        searchpath = self.LDAP_USER_BASE
        # This should probably look like...
        # (&(givenName=%s)(sn=%s))
        # Search for first & last name exactly:
        #search = '(&(givenName=%s)(sn=%s))' % (first, last)
        # Search for first + last name:
        search = ('(&(objectClass=user)(!(objectClass=computer))'
                  '(sn=%s)(givenName=%s))') % (last, first)

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['givenName', 'sn', 'employeeNumber'])

        if not len(result):
            return 0
        else:
            return result

    def move(self, srcDN, destDN):
        """ Move an object from srcDN to destDN.

        .. todo:: Should not use print statements here.
        """

        # (srcdn, newrdn, destdn)
        # self.ldap_client.rename_s(
        #     'CN=Joe D Doe,OU=Users,DC=domain,DC=com',
        #     'CN=Joe D Doe',
        #     'OU=OldUsers,DC=domain,DC=com'
        # )

        rdn = srcDN.split(',')[0]
        print srcDN
        print rdn
        print destDN

        self.ldap_client.rename_s(srcDN, rdn, destDN)

    def move2(self, samaccountname, destOU):
        """
        Move an object, samaccountname, to destDN.

        .. note:: This uses code not available until python-ldap v2.3.2. On
                  RHEL/CentOS 5.8, repositories only have python-ldap v2.2.0.

        :param samaccountname: The accountname to search and move.
        :param destOU: the folder to move the samaccountname into.
        """

        # rename_s syntax:
        # >>> self.ldap_client.rename_s(
        #     'CN=Jane D Doe,OU=Users,DC=domain,DC=com',
        #     'CN=Jane D Doe',
        #     'OU=OldUsers,DC=domain,DC=com'
        #     )

        srcDN = ldap.dn.explode_dn(ad.get_dn_from_sn(samaccountname))

        rdn = srcDN[0]

        self.ldap_client.rename_s(",".join(srcDN),
                                  rdn,
                                  destOU)

    def renameUser(self, old_username, new_username):
        """ Rename a given AD object """

        u = self.getuser(old_username)
        if u:
            # Replace <old>@DOMAIN.FQDN with <new>@DOMAIN.FQDN using
            # str().replace() method.
            u.userPrincipalName = u.userPrincipalName.replace(old_username,
                                                              new_username)
            u.sAMAccountName = new_username
            u.commit()

################
# PROTOTYPE USER OBJ FUNCTIONS
############
    def getattrs_by_filter(self, key, value,
                           attrlist=None,
                           base=None,
                           pageSize=1000,
                           compare='=',
                           addt_filter=''):
        '''Search AD by attribute.

        :param attrlist: The attributes desired (None for all)
        :type attrlist: list

        :param compare: Comparison, valid operators: =, >=, <=
          (lexicographical)

        :return: A list of result dictionaries.

        Examples:
            >>> mldapObj.getattrs_by_filter("sAMAccountName",
                                            "wimpy")[0]['sAMAccountName']
            'wimpy'

            >>> mldapObj.getattrs_by_filter("sAMAccountName",
                                            "wimpy")[0]['objectClass']
            ['top', 'person', 'organizationalPerson', 'user']

        '''
        if base is None:
            base = self.LDAP_USER_BASE

        search = None

        # To handle searches for None values (to answer who DOESN'T
        # have an e-mail attribute set?), the search filter should use
        # the not-present operator: (!attribute_name=*) to test for
        # the absence of an attribute
        if value is None:
            search = ("(&(!(objectClass=computer))"
                      "(!(objectClass=organizationalUnit))"
                      "(!(%s=*))%s)") % (str(key),
                                         addt_filter)

        elif key == 'objectGUID':
            search = "(&(!(objectClass=computer))(%s%s%s)%s)" % (
                str(key),
                compare,
                ldap.filter.escape_filter_chars(str(value)),
                addt_filter)
        else:
            search = "(&(!(objectClass=computer))(%s%s%s)%s)" % (
                str(key),
                ldap.filter.escape_filter_chars(compare),
                str(value),
                addt_filter)

        lc = ldap.controls.SimplePagedResultsControl(
            ldap.LDAP_CONTROL_PAGE_OID, True, (pageSize, ''))

        msgid = self.ldap_client.search_ext(
            base,
            ldap.SCOPE_SUBTREE,
            search,
            serverctrls=[lc],
            attrlist=attrlist)

        results = []
        pages = 0

        while True:
            pages += 1
            rtype, rdata, rmsgid, serverctrls = self.ldap_client.result3(msgid)

            # Each result tuple (rdata) is of the form (dn, attrs),
            # where dn is a string containing the DN (distinguished
            # name) of the entry, and attrs is a dictionary containing
            # the attributes associated with the entry. The keys of
            # attrs are strings, and the associated values are lists
            # of strings.

            for (dn, entry) in rdata:
                if dn is not None:
                    results.append(entry)

            pctrls = [
              c
              for c in serverctrls
              if c.controlType == ldap.LDAP_CONTROL_PAGE_OID
            ]
            if pctrls:
                est, cookie = pctrls[0].controlValue
                if cookie:
                    lc.controlValue = (pageSize, cookie)
                    msgid = self.ldap_client.search_ext(
                        base,
                        ldap.SCOPE_SUBTREE,
                        search,
                        serverctrls=[lc],
                        attrlist=attrlist)
                else:
                    break
            else:
                print "Warning:  Server ignores RFC 2696 control."
                break

        for result in results:
            for attr in result:
                result[attr] = flatten(result[attr])

        return results

    def getattr_by_filter(self, key, value, attr):
        """Performance a search to match an object by attribute value.

        :return: The requested value, or None.

        Examples:

        Get the mail attribute from an AD object identified by
        sAMAccountName = "wimpy":
          >>> mldapObj.getattr_by_filter('sAMAccountName', 'wimpy', 'mail')
          'wimpy@wimpy.org'

        Get the objectClass from an AD object identified by
        sAMAccountName = "wimpy":
          >>> mldapObj.getattr_by_filter('sAMAccountName',
                                         'wimpy',
                                         'objectClass')
          ['top', 'person', 'organizationalPerson', 'user']

        """

        result = self.getattrs_by_filter(key, value)

        try:
            return result[0][attr]
        except:
            return None

    def getusers_by_filter(self, attr, value):
        """ Retrieve a list of users by filter.

        :param attr: AD attribute (sAMAccountName, etc)
        :type attr: str

        :return: a list of :mod:`aduser.ADuser` objects

        Examples:

            >>> user = self.getusers_by_filter(attr, value)

        """
        attributes = self.getattrs_by_filter(attr, value)
        users = []
        for attribute in attributes:
            users.append(ADuser(attribute['sAMAccountName'],
                                ad_obj=self, attributes=attribute))

        return users

    def getuser_by_filter(self, attr, value):
        """ Retrieve a single user by filter.

        Raises Exception if there is more than one match to the filter.

        :param attr: AD attribute (sAMAccountName, etc)
        :type attr: str

        :return: a list of :mod:`aduser.ADuser` objects or
          `None` if there is no match.

        Examples:

            >>> user = self.getusers_by_filter(attr, value)

        """

        users = self.getusers_by_filter(attr, value)

        if len(users) == 1:
            return users[0]
        elif len(users) == 0:
            return None
        else:
            raise Exception("TooManyObjects from getuser by filter")

    def getuser(self, samaccountname_or_dn):
        """Return an object of type ADUser for a given sAMAccountName or DN"""
        if '=' in samaccountname_or_dn:
            samaccountname = self.get_sn_from_dn(samaccountname_or_dn)
        else:
            samaccountname = samaccountname_or_dn

        attributes = self.getattr(samaccountname)
        if attributes is not None:
            return ADuser(samaccountname, ad_obj=self,
                          attributes=self.getattr(samaccountname))
        else:
            return None

    def getgroup(self, group):
        """Return `group` as a :mod:`adgroup.ADgroup` object. If no such
        group is found, returns an empty :mod:`adgroup.ADgroup` object."""

        g = ADgroup(group, self.get_dn_from_sn(group))
        for user in self.bgroup(group):
            if user[0] is None:
                continue
            attr_set = self.unpack_attributes(user)
            u = ADuser(attr_set['sAMAccountName'],
                       attributes=attr_set,
                       ad_obj=self)
            g.members.append(u)
        return g

    def getusers(self, base=None, objectType='samaccountname'):
        """
        Retrieve a list of :class:`aduser.ADuser` objects (a more
        Object-Oriented version of :func:`adcon.mldap.listou`)
        """
        if base is None:
            base = self.LDAP_USER_BASE
        search = '%s=*' % (objectType)
        results = self.ldap_client.search_s(
            base,
            ldap.SCOPE_SUBTREE,
            search,
            ['*'])

        ret = list()

        for (dn, attrs) in results:
            if dn is None:
                continue

            ret.append(ADuser(attrs['sAMAccountName'], attrs, ad_obj=self))

        return ret

# all is well, close connection
    def disconnect(self):
        """ Close the AD/LDAP Connection if it is open. """
        try:
            self.ldap_client.unbind()
        except ldap.LDAPError:
            # Prevent crashes on multiple disconnect() calls.
            pass
