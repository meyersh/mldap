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
import os
import sys
import warnings
import ldap
from ldap.controls import SimplePagedResultsControl
import datetime
import ConfigParser
import base64 # for password obfuscation

import pprint

__version__ = "1.0.3"

# Enable all warnings
warnings.simplefilter('default')

def deprecated(message=None):
    ''' Call this function with an optional message to raise a warning
    for a depracated function. '''
    if message is None:
        message = "This function is deprecated."
    warnings.warn(message, DeprecationWarning, stacklevel=3)


#
## Read up the configuration stuff (or die trying)
#

CREDSFILE = '/etc/ldap.creds'

def read_creds(credsfile = None):
    """ Read in the config file and return its data as a dictionary.
    
    Example:
    [LDAP]
    SERVER=ldap://my.server.url
    USERNAME=administrator@my.domain.url
    PASSWORD=some_base64_encoded_str=
    BASE=dc=my,dc=domain,dc=url
    DOMAIN=my.domain.url
    USER_BASE=ou=Users,dc=my,dc=domain,dc=url
    GROUP_BASE=ou=Groups,dc=my,dc=domain,dc=url
    ...

    @return: Dictionary with keys(): ('LDAP_USERNAME', 'LDAP_PASSWORD',
    'LDAP_SERVER', 'LDAP_BASE', 'LDAP_DOMAIN')
    """

    if credsfile is None:
        credsfile = CREDSFILE

    config = ConfigParser.RawConfigParser()
    config.read(credsfile)

    assert config.has_section('LDAP')

    creds = {
        'LDAP_USERNAME': config.get('LDAP', 'username'),
        'LDAP_PASSWORD': base64.b64decode(config.get('LDAP', 'password')),
        'LDAP_SERVER': config.get('LDAP', 'server'),
        'LDAP_BASE': config.get('LDAP', 'base'),
        'LDAP_DOMAIN': config.get('LDAP', 'domain')
        }

    # Handle optional fields.
    if config.has_option('LDAP', 'group_base'):
        creds['LDAP_GROUP_BASE'] = config.get('LDAP', 'group_base')
    else:
        creds['LDAP_GROUP_BASE'] = creds['LDAP_BASE']

    if config.has_option('LDAP', 'user_base'):
        creds['LDAP_USER_BASE'] = config.get('LDAP', 'user_base'),
    else:
        creds['LDAP_USER_BASE'] = creds['LDAP_BASE']

    return creds
        
#creds = read_creds()

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

################################################################################
# ADuser & ADGroup Classes
################################################################################

class ADuser(object):

    attr_map = {
        'firstname': 'givenName',
        'initial': 'initials',
        'lastname':'sn',
        'idno': 'employeeNumber',
        'email': 'mail',
        'distinguishedName': 'distinguishedName'
        }

    ''' attributes that are allowed to be written back to AD '''
    writable_attributes = [ 'mail',
                            'givenName',
                            'initials',
                            'sn',
                            'employeeNumber',
                            'userPrincipalName'
        ]

    # def deduce_usertype_from_dn(self):
    #     """ Attempt to deduce the usertype field from the dn.
    #     @return: the usertype OR the head of the DN (sans const.BASE)
    #     if no type matches. """

    #     o = self.dn
    #     o = o.replace(','+const.BASE, '') # remove BASE portion
    #     o = ",".join(o.split(',')[1:]) # remove CN= head portion
        
    #     if o in const.rev_usertype_map:
    #         return const.rev_usertype_map[o]
        

    #     ''' usertype is not recognized, 
    #     return partial OU head for debug. '''
    #     return self.dn.replace(','+const.BASE, '')

    def _get_info(self):
        ad_attributes = {'givenName':None, 'initials':None, 'sn':None, 'employeeNumber':None, 'mail':None, 
                            'memberOf':None, 'distinguishedName':None}

        ad_attributes.update(ad.getattr(self.username, ad_attributes.keys()))
                       
        self.firstname = ad_attributes['givenName']
        self.initial   = ad_attributes['initials']
        self.lastname  = ad_attributes['sn']
        self.idno      = ad_attributes['employeeNumber']
        self.email     = ad_attributes['mail']
        self.dn        = ad_attributes['distinguishedName']
        self.expired   = self.adcon.isexpired(self.username)
        self.usertype  = self.deduce_usertype_from_dn()

        self.guid      = self.adcon.getattr(self.username, 'objectGUID')

        if ad.isdisabled(self.username):
            self.networkstatus = "DISABLED"
        else:
            self.networkstatus = "ENABLED"

    def __init__(self, username, ad_obj = None, attributes = None):

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
        self.__init__(self.username)

    def commit(self):
        ''' commit back attribute changes to active directory '''
        if self.initiated is False or self.adcon.exists(self.username) is False:
            return

        ''' This will handle all easy attributes '''
        for attr in self.writable_attributes:
            if self.__getattribute__(attr) != self.adcon.getattr(self.username, ad_attr):
                print "%s: mismatch: %s" % (self.sAMAccountName, attr)
                #adcon.replace(self.username, ad_attr, self.__getattribute__(attr))

        ''' Handle username changes? '''
        

    def update_from(self, other):
        ''' update user attributes from another user type. '''
        assert isinstance(self, other.__class__)

    def __repr__(self):
        if 'cn' in self.__dict__:
            return "<ADUser: '%(cn)s' (%(sAMAccountName)s)>" % self.__dict__
        else:
            return "<AD User Object(uninitialized)>"
        
    def __eq__(self, other):
        return self.objectGUID == other.objectGUID


class ADgroup(object):
    def __init__(self, groupname, dn, ad_obj=None):
        self.__dict__ = {'dn':dn, 'name':groupname, 'members':list()}
        self.ad = ad_obj
    def __len__(self):
        return len(self.members)
    def __contains__(self, user):
        return user in self.members
    def __iter__(self):
        return iter(self.members)
    def __repr__(self):
        return "<ADGroup: '%s' having %d users>" % (
            self.name, len(self.members))
    
################################################################################
# Some UAC (user Account Control) codes
################################################################################
class uac(object):
    """ A quick definition of some constants in the 
    userAccountControl attribute. """
 
    """ Default value (0) """
    uac_value = 0

    """ The logon script is executed. """
    ADS_UF_SCRIPT = 0x00000001

    """ The user account is disabled. """
    ADS_UF_ACCOUNTDISABLE = 0x00000002

    """ The home directory is required. """
    ADS_UF_HOMEDIR_REQUIRED = 0x00000008

    """ The account is currently locked out. """
    ADS_UF_LOCKOUT = 0x00000010

    """  No password is required.  """
    ADS_UF_PASSWD_NOTREQD = 0x00000020

    """ The user cannot change the password.  Note You cannot assign
    the permission settings of PASSWD_CANT_CHANGE by directly modifying
    the UserAccountControl attribute. For more information and a code
    example that shows how to prevent a user from changing the password,
    see User Cannot Change Password. 
    (http://msdn.microsoft.com/en-us/library/aa746508(v=vs.85).aspx ) """
    ADS_UF_PASSWD_CANT_CHANGE = 0x00000040

    """ The user can send an encrypted password. """
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080

    """ This is an account for users whose primary account is in
    another domain. This account provides user access to this domain,
    but not to any domain that trusts this domain. Also known as a
    local user account. """
    ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100

    """ This is a default account type that represents a typical user. """
    ADS_UF_NORMAL_ACCOUNT = 0x00000200

    """ This is a permit to trust account for a system domain that trusts 
    other domains. """
    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800

    """ This is a computer account for a computer that is a member of this 
    domain. """
    ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000

    """ This is a computer account for a system backup domain controller that 
    is a member of this domain. """
    ADS_UF_SERVER_TRUST_ACCOUNT = 0x00002000

    """ The password for this account will never expire. """
    ADS_UF_DONT_EXPIRE_PASSWD = 0x00010000

    """ This is an MNS logon account. """
    ADS_UF_MNS_LOGON_ACCOUNT = 0x00020000

    """ The user must log on using a smart card. """
    ADS_UF_SMARTCARD_REQUIRED = 0x00040000

    """ The service account (user or computer account), under which a
    service runs, is trusted for Kerberos delegation. Any such service
    can impersonate a client requesting the service. """
    ADS_UF_TRUSTED_FOR_DELEGATION = 0x00080000

    """ The security context of the user will not be delegated to a
    service even if the service account is set as trusted for Kerberos
    delegation. """
    ADS_UF_NOT_DELEGATED = 0x00100000

    """ Restrict this principal to use only Data Encryption Standard
    (DES) encryption types for keys. """
    ADS_UF_USE_DES_KEY_ONLY = 0x00200000

    """ This account does not require Kerberos pre-authentication for
    logon. """
    ADS_UF_DONT_REQUIRE_PREAUTH = 0x00400000

    """ The user password has expired. This flag is created by the
    system using data from the Pwd-Last-Set attribute and the domain
    policy. """
    ADS_UF_PASSWORD_EXPIRED = 0x00800000

    """ The account is enabled for delegation. This is a
    security-sensitive setting; accounts with this option enabled
    should be strictly controlled. This setting enables a service
    running under the account to assume a client identity and
    authenticate as that user to other remote servers on the
    network. """
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000

    @classmethod
    def flags(cls, value):
        """ iterate through flags (using dir()) and return a human-legible
        rendition of account flags. """

        value = int(value)
        ret = list()
        for flag in dir(uac):
            if 'ADS' in flag:
                if value & cls().__getattribute__(flag):
                    ret.append(flag)

        return ret    

    def instance_flags(self):
        """ @return: a list of user-readable flags which are set. """
        return uac.flags(self.uac_value)

    def set(self, flag):
        self.uac_value |= int(flag)
        return self

    def unset(self, flag):
        self.uac_value &= (~int(flag) & 0xFFFFFFFF)
        return self

    def is_set(self, flag):
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
        try:
            self.ad.setuac(self.samaccountname, self)
        except:
            raise Exception("No AD data member to commit")

    def __init__(self, value=0):
        self.ad = None
        self.samaccountname = None

        self.uac_value = int(value)
        self.flags = self.instance_flags


###############################################################################
###############################################################################
#
# BEGIN MLDAP OBJECT DEFINITION
#
###############################################################################
###############################################################################

class mldap:
    """ This class is specifically designed to connect to and interact with 
    our Active Directory via LDAP. 
    
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
        """ Read default creds file. If keyword credentials are specified 
        during object instantiation, those superceded the file. 

        @type creds: Dictionary
        @param creds: Dictionary which optionally contains LDAP_USERNAME,
        LDAP_PASSWORD, or LDAP_SERVER keys to override what is loaded from 
        the credsfile variable.
        """
        credsfile = args.get('credsfile') if args.get('credsfile') else CREDSFILE

        if os.path.exists(credsfile):
            self.__dict__.update(read_creds(args.get('credsfile')))

        self.__dict__.update(args)

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
            print "Invalid credentials: ",e
            sys.exit()
        except ldap.SERVER_DOWN, e:
            print "Your server (%s) appears to be down." % self.LDAP_SERVER
            for error in e:
                print "  %(info)s\n  %(desc)s" % (error)
            sys.exit()

        return self.ldap_client


    # TODO: Remove this function!                             
    def checkidno(self, idno):
        """ Taking an IDNO as only argument, does a search in the
        employeeNumber LDAP field for this value.

        @param idno: string containing the users 7-digit ID.NO

        @return:
            sAMAccountName or None
        """
        searchpath=self.LDAP_USER_BASE
        search = '(&(employeeNumber=%s))' % ( idno )
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName','sAMAccountName'])

        if not len(result):
            return None
        else:
            if 'sAMAccountName' in result[0][1]:
                return result[0][1]['sAMAccountName'][0]


# 
# Check if an account exists based on the presence of a sAMAccountName
#

    def exists(self, samaccountname):
        """ Check if an account exists based on the presence of a sAMAccountName 
        @return: True/False """
        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(samaccountname)
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
               objectType='samaccountname',
               pageSize=5000):
        """ List all sAMAccountNames of a given OU """
        if base is None:
            base = self.LDAP_USER_BASE
        search = '%s=*' % (objectType)

        lc = SimplePagedResultsControl(
            ldap.LDAP_CONTROL_PAGE_OID,True,(pageSize,''))

        msgid = self.ldap_client.search_ext(
            base,
            ldap.SCOPE_SUBTREE,
            search,
            serverctrls=[lc])

        results=[]
        pages = 0
        
        while True:
            pages += 1
            rtype, rdata, rmsgid, serverctrls = self.ldap_client.result3(msgid)
            for dn,entry in rdata:
                if dn is not None:
                    results += entry['sAMAccountName']

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
                        serverctrls=[lc])
                else:
                    break
            else:
                print "Warning:  Server ignores RFC 2696 control."
                break

        return results

#
# Replace/Set the value of a given attribute for the specified user.
#

    def replace(self, samaccountname, attribute, value):
       """ Replace/Set the value of a given attribute for the 
       specified user. """
       mod_attrs = [( ldap.MOD_REPLACE, attribute, value )]
       dn=self.get_dn_from_sn(samaccountname)
       if dn is None:
           raise NoSuchObject(samaccountname)
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

        @type samaccountname: String
        @param samaccountname: Username to create
        
        @type cn: String
        @param cn: CN of new account (only the CN=(whatever))
        
        @type path: String
        @param path: ldap path of OU for new account

        @type CONSTattributes: Dictionary
        @param CONSTattributes: A dict of LDAP attributes for the new account.
        
        """

        # Dictionaries are passed by reference, I do not want to 
        # modify it outside of function scope. 
        # SRGM - Jun 1, 2010
        attributes = dict(CONSTattributes)

        if not self.exists(samaccountname):
            dn="CN=%s,%s" % (cn, path)
           
            # The default password is 'changeme'
            if 'password' not in attributes:
                attributes['password'] = 'changeme'

            # Encode password as unicode for AD.
            unicode1 = unicode("\"" + attributes['password'] + "\"", "iso-8859-1")
            unicode2 = unicode1.encode("utf-16-le")
            attributes['password'] = unicode2

            # TODO: Make this more general
            userprincipalname="%s@%s" % (samaccountname, self.LDAP_DOMAIN)

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
                    entry=(i, attributes[i])
                    add_record.append(entry)

            try:
                self.ldap_client.add_s(dn, add_record)
            except ldap.CONSTRAINT_VIOLATION, info:
                print info
        else:
            print "sAMAccountName '%s' already exists!" % samaccountname

    def create_group(self, groupname, path, members=[]):
        """ Create a new group with the specified members.

        @type groupname: String
        @param groupname: Group name to create
        
        @type path: String
        @param path: base CN of new group
        
        @type members: List
        @param members: A list of members to pre-populate group.
        
        """

        if self.exists(groupname):
            return False # Group already exists.

        # Try to massage the members list into a list of DN's
        group_members = list()
        if members:
            for m in list(set(members)): # no duplicates
                if ad.exists(m):
                    group_members.append(ad.get_dn_from_sn(m))

        dn="CN=%s,%s" % (groupname, path)
           
        add_record = [
            ('objectclass', ['top', 'group']),
            ('samaccountname', groupname),
            ('cn', groupname)
            ]
        
        try:
            self.ldap_client.add_s(dn, add_record)
            for m in group_members:
                add_to_group(m, groupname)
        except ldap.CONSTRAINT_VIOLATION, info:
            print info


    def try_member_search(self, sAMAccountName):
        searchpath=('cn=group,dc=base')

        search = '(member=%s)' % self.get_dn_from_sn(sAMAccountName)

        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,['distinguishedName'])

        if not len(result):
            return 0
        else:
            return result[0][0] # We need a more reliable way to get this info.

#
# Return a DN for a given SN (sAMAccountName)
#

    def get_dn_from_sn(self,samaccountname):
        """ Return a DN for a given sAMAccountName """
        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(samaccountname)
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        if not len(result):
            return 0
        else:
            return result[0][0] # We need a more reliable way to get this info.

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
       """ Replace/Set the value of a given attribute for the specified user (by IDNO). """
       mod_attrs = [( ldap.MOD_REPLACE, attribute, value )]
       dn=self.get_dn_from_idno(idno)
       self.ldap_client.modify_s(dn, mod_attrs)

    def get_dn_from_idno(self, idno):
        """ Return a DN for a given ID.NO """
        searchpath=self.LDAP_USER_BASE
        search = 'employeeNumber='+str(idno)
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            ['distinguishedName'])

        # Deal with NO results:
        if not len(result):
            return 0

        # Deal with Multiple results (Should not happen):
        #elif len(result) > 1:
        #    print "ERROR! Search returned multiple results for IDNO %s " % idno
        #    print result
        #    return 0
        assert len(result) == 1

        return result[0][0] # Return the first DN from our results 
                            # (no way we got two, right??)

#
# Return a given sn's idno
#

    def get_idno_from_sn(self, sAMAccountName):
        """ Return a given SN's idno.
        @return:  None if an error occurs."""
        try:
            idno = self.getattr(sAMAccountName, 'employeeNumber')
            
            return idno

        except KeyError:
            return None

#
#
#

    def resetpw(self, sAMAccountName, newpass):
        """ Wraps around L{self.replace()} to reset a given 
        password. Note: This attempts the administrative 
        reset with whatever user this module binds with so 
        make sure that it has the proper AD permissions. """
        
        # Encode password as unicode for AD.
        unicode1 = unicode("\"" + newpass + "\"", "iso-8859-1")
        unicode2 = unicode1.encode("utf-16-le")
        unicodePwd = unicode2 # Our unicoded password.

        self.replace(sAMAccountName, 'unicodePwd', unicodePwd)





################################################################################
# A few group functions
################################################################################

#
# Adds a user to a given group.
#

    def add_to_group(self, sAMAccountName, groupCN):
        """ Add a user to a given group """
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
        """ Return a list of a given groups' members """
        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(groupCN)
        attrs=['member', 'objectClass']

        result = self.ldap_client.search_s(
            searchpath,ldap.SCOPE_SUBTREE,search,attrs)
        #members=result[0][1]['member']
        members = result
        
        return members

    #
    # Return all attributes for all users who are memberOf= a given group
    #
    def bgroup(self, group):
        filter= "(&(memberOf=%s))" % self.get_dn_from_sn(group)
        i = self.ldap_client.search(self.LDAP_BASE,
                                  ldap.SCOPE_SUBTREE,
                                  filterstr=filter)
        return self.ldap_client.result(i)[1]

    def unpack_attributes(self, result_set):
        r = result_set[1] # the actual results..
        unpacked_set = dict()
        for attr in r:
            if len(r[attr]) == 0:
                unpacked_set[attr] = None
            elif len(r[attr]) == 1:
                unpacked_set[attr] = r[attr][0]
            elif len(r[attr]) > 1:
                unpacked_set[attr] = r[attr]
        return unpacked_set


# 
# Returns a given set of attributes for an SN, probably superceded by
# getattr()
#

    def checkuser(self, samaccountname):
        """ Superceded by self.getattr() """
        searchpath=self.LDAP_BASE
        # This should probably look like...
        # (&(givenName=%s)(sn=%s))
        # Search for first & last name exactly:
        #search = '(&(givenName=%s)(sn=%s))' % (first, last)
        # Search for first + last name:
        search = 'samaccountname='+str(samaccountname)
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

    def isset(self, samaccountname, attr, value):
        """ Verify sAMAccountName object has attr set to value.
        Except: ldap.NO_SUCH_ATTRIBUTE"""

        dn = self.get_dn_from_sn(samaccountname)
        try:
            return self.ldap_client.compare_s(dn, attr, value)
        except ldap.NO_SUCH_ATTRIBUTE:
            return 0

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

        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(samaccountname)
        
        # Determine if attr is str or list type:
        if type(attr).__name__ == 'str':
            attrs = [attr]
        elif type(attr).__name__ == 'list':
            attrs=attr
          
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
        getattr(sAMAccountName, [attr1, attr2, ...])
        getattr(samaccountname) """

        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(samaccountname)
        
        # Determine if attr is str or list type:
        if type(attr).__name__ == 'str':
            attrs = [attr]
        elif type(attr).__name__ == 'list':
            attrs=attr
          
        result = self.ldap_client.search_s(
            searchpath,
            ldap.SCOPE_SUBTREE,
            search,
            attrs)

        attributes=result[0][1] # Because they nest it so darn deep!

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
        getattr(sAMAccountName, [attr1, attr2, ...])
        getattr(samaccountname) 

        @param attr:  String containing one LDAP attribute, a list of 
        LDAP attributes, or a string containing '*' to return all 
        attributes.

        @return: attr, a dictionary with attr keys. Multiple results 
        are returned as a list."""

        if not self.exists(samaccountname):
            return None

        searchpath=self.LDAP_BASE
        search = 'samaccountname='+str(samaccountname)
        
        if isinstance(attr, str):
            attrs = [attr]
        else:
            attrs = list(attr)

        result = self.ldap_client.search_s(
            searchpath,ldap.SCOPE_SUBTREE,search,attrs)

        attributes=result[0][1] # Because they nest it so darn deep!

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

        @return: a uac object derived from these flags. 
        """
        userAccountControl_flags = int(
            self.getattr(samaccountname, 'userAccountControl'))

        user_uac = uac(userAccountControl_flags)
        user_uac.ad = self
        user_uac.samaccountname = samaccountname

        return user_uac


    def setuac(self, samaccountname, new_uac):
        """ Set the uac field for a given user.  
        @param new_uac: The decimal representation of the
        userAccountControl field (actually, any input is ok as long as
        it converts properly with str() which at this time means
        string, uac object, or int. This means '512', 512, uac(512)
        are all acceptable. """
        self.replace(samaccountname, 'userAccountControl', str(new_uac))


    def isdisabled(self, samaccountname):
        """ Is a given SN disabled? """
        return self.getuac(samaccountname).is_set(
            uac.ADS_UF_ACCOUNTDISABLE)

    def isexpired(self, samaccountname):
        """ Is a given SN expired? 
        accountExpires is the number of ticks (100n/s [.0000001s])
        since 12:00AM Jan 1, 1601. Thanks, Microsoft. 
        Additionally, it's in UTC

        If a user object in Active Directory has never had an
        expiration date, the accountExpires attribute is set to a huge
        number. The actual value is 2^63 - 1, or
        9,223,372,036,854,775,807. 
        """

        winnt_epoch = datetime.datetime(1601, 1, 1, 0, 0)
        
        winnt_time = int(self.getattr(samaccountname, 'accountExpires'))
        winnt_time /= 10000000 # Convert to seconds

        never_expires = 922337203685L

        if winnt_time == never_expires or winnt_time == 0:
            return False;

        expiration_date = winnt_epoch + datetime.timedelta(seconds=winnt_time)

        return datetime.datetime.now() > expiration_date
        
# 
# Search AD for a given first and last name.
#

    def search(self, first, last):
        searchpath=self.LDAP_USER_BASE
        # This should probably look like...
        # (&(givenName=%s)(sn=%s))
        # Search for first & last name exactly:
        #search = '(&(givenName=%s)(sn=%s))' % (first, last)
        # Search for first + last name:
        search = ('(&(objectClass=user)(!(objectClass=computer))'
                  '(sn=%s)(givenName=%s))') % (last,first)

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
        ''' (srcdn, newrdn, destdn) ''' 
        ''' self.ldap_client.rename_s(
          'CN=Joe D Doe,OU=Users,DC=domain,DC=com',
          'CN=Joe D Doe',
          'OU=OldUsers,DC=domain,DC=com'
        ) '''

        rdn = srcDN.split(',')[0]
        print srcDN
        print rdn
        print destDN

        self.ldap_client.rename_s( srcDN, rdn, destDN )

    def move2(self, samaccountname, destOU):
        """ This uses code not available in the older version of
        LDAP - consider it testing/alpha. 
        param samaccountname: The accountname to search and move.
        param destOU: the folder to move the samaccountname into. 

        >>> self.ldap_client.rename_s(
            'CN=Jane D Doe,OU=Users,DC=domain,DC=com', 
            'CN=Jane D Doe', 
            'OU=OldUsers,DC=domain,DC=com'
            )
            """

        srcDN = ldap.dn.explode_dn(ad.get_dn_from_sn(samaccountname))
        
        rdn = srcDN[0]
        
        self.ldap_client.rename_s( ",".join(srcDN),
                                   rdn,
                                   destOU )

    def renameUser(self, old_username, new_username):
        ad.replace(old_username, 'sAMAccountName', new_username)
        UPN_suffix = ad.getattr(new_username, 'userPrincipalName').split('@')[1]
        ad.replace(new_username, 'userPrincipalname', '%s@%s'%  (new_username, UPN_suffix))
                                   
################
# PROTOTYPE USER OBJ FUNCTIONS
############

    def getattr_by_filter(self, key, value):
        ''' Return a list of object of type ADUser given an attribute
        to search on. '''
        search = None
        if key == 'objectGUID':
            search = "(&(!(objectClass=computer))(%s=%s))" % (str(key), ldap.filter.escape_filter_chars(str(value)))
        else:
            search = "(&(!(objectClass=computer))(%s=%s))" % (str(key), str(value))

        searchpath='dc=mustang,dc=morningside,dc=edu'

        result = self.ldap_client.search_s(searchpath,ldap.SCOPE_SUBTREE,search,[])

        attributes=result[0][1] # Because they nest it so darn deep!

        ret = []

        for (dn, attrs) in result:
            if dn is None:
                continue

            for attr in attrs:
                attrs[attr] = flatten(attrs[attr])
                
            ret.append(attrs)
            
            

        return ret


    def getuser_by_filter(self, matchfilter, attr="*"):
        """ Lookup attributes on a given user(s) by filter. If 
        not specified, return all attributes.
        getattr(objectGUID, [attr1, attr2, ...])
        getattr(objectGUID) 

        @return: attr, a dictionary with attr keys. Multiple results 
        are returned as a list."""


        # "ad.exists()"
        """ Check if an account exists based on the presence of a sAMAccountName 
        @return: True/False """
        search = "%s" % ldap.filter.escape_filter_chars(str(matchfilter))
        searchpath='dc=mustang,dc=morningside,dc=edu'

        result = self.ldap_client.search_s(searchpath,ldap.SCOPE_SUBTREE,search,['objectGUID'])
        if "objectGUID" not in result[0][1]:
            return None

        # Determine if attr is str or list type:
        if type(attr).__name__ == 'str':
            attrs = [attr]
        elif type(attr).__name__ == 'list':
            attrs=attr
          
        result = self.ldap_client.search_s(searchpath,ldap.SCOPE_SUBTREE,search,attrs)

        attributes=result[0][1] # Because they nest it so darn deep!

        # This reorganizes the results. Normally the ldap module allows you to get
        # many accounts' worth of results back in one go so we end up with a 
        # dictionary of lists. Ugh, we're only getting one back here so this 
        # cleans up a lot. If we passed multiple attributes we get a dict back
        # if we passed one we get a list with one item...

        result = {}
        for i in attributes:
            if len(attributes[i]) == 0:
                result[i] = None
            if len(attributes[i]) == 1:
                result[i] = attributes[i][0]

            elif len(attributes[i]) > 1:
                result[i] = attributes[i]

        if (attr == "*" or type(attr) == type(list())):
            return result
        else:
            if attr in result:
                return result[attr]
            else:
                return None
         

    def getuser(self, samaccountname_or_dn):
        """ Return an object of type ADUser for a given sAMAccountName or DN """
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
        g = ADgroup(group, self.get_dn_from_sn(group))
        for user in self.bgroup(group):
            if user[0] == None:
                continue
            attr_set = self.unpack_attributes(user)
            u = ADuser(attr_set['sAMAccountName'], attributes=attr_set, ad_obj=self)
            g.members.append(u)
        return g

    def getusers(self, base=None, objectType='samaccountname'):
        if base is None:
            base = self.LDAP_USER_BASE
        search = '%s=*' % (objectType)
        results = self.ldap_client.search_s(
            base,ldap.SCOPE_SUBTREE,search,['*'])

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
            pass # Prevent crashes on multiple disconnect() calls.
            

class NoSuchObject(Exception):
    """ Provide a custom exception to call when we have no user to
    perform an action upon. """
    pass
