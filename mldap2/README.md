# MLDAP Doc

`mldap2` is a thin wrapper around the python-ldap library written to
operate against our 2003-based Active Directory.Specifically, it is
used to programmatically create, delete, modify, and query active
directory via the LDAP protocol by lifting the programmer away from
the context of working with LDAP and filters to working with user
attributes and groups.

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


# EXAMPLES

## Basic connection, verify a user account.
```python
>>> include mldap
>>> ad = mldap2.connect({'LDAP_USERNAME': 'your-ad-user@your-domain',
...                      'LDAP_PASSWORD': 'xxxxx',
...                      'LDAP_BASE': 'dc=YOUR,dc=DOMAIN'})
>>> ad.exists('some-username')
True
```

## Operate on a series of accounts (for instance, to change mail domains.)
```python
ad = mldap2.connect('''creds''')
users = ad.getusers_by_filter('mail', '*@olddomain.com')
for user in users:
  user.mail.replace('@olddomain.com', '@newdomain.com') # user.mail is just a string.
  user.commit() # updates any modified fields.
```

## Help!
```
>>> help(ad)
```
