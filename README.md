# MLDAP Doc

`mldap` is a thin wrapper around the python-ldap library written to operate
against our 2003-based Active Directory.

Specifically, it is used to programmatically create, delete, modify, and
query active directory via the LDAP protocol.

# GOTCHA'S

A few AD functions require `ldaps` security and it is recommended to use `ldaps`
for all connections. On campus we connect via the domain dns address which,
by default, resolves to a round-robin of all domain controllers.

Accordingly, connecting to `ldaps://domain.url` may invoke surprising SSL
certificates. If you have trouble with ldap and ssl you may need to adjust
your ldap.conf (perhaps located in `/etc/openldap/ldap.conf`). In our case
adding `TLS_REQCERT allow` was a satisfactory work-around.

# INSTALLATION

Drop mldap.py into your python include path and include it.

EXAMPLES
========
```python
>>> import mldap
>>> ad = mldap.mldap(LDAP_USERNAME='ldapuser',
                     LDAP_PASSWORD='xxxxxx',
                     LDAP_SERVER='ldaps://dc4.domain.tld',
                     LDAP_BASE='DC=domain,DC=tld',
                     LDAP_USER_BASE='OU=Users,DC=domain,DC=tld',
                     LDAP_GROUP_BASE='OU=Groups,DC=domain,DC=tld',
                     LDAP_DOMAIN='DOMAIN')
>>> ad.exists('ldapuser')
True

>>> help(mldap.mldap)
```
