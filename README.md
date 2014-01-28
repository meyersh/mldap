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

Drop mldap.py into your python include path and include it. You will need
to create a configuration file for your network (default location is in 
/etc/ldap.creds).

credsfile example:
```
    [LDAP]
    SERVER=ldap://my.server.url
    USERNAME=administrator@my.domain.url
    PASSWORD=some_base64_encoded_str=
    BASE=dc=my,dc=domain,dc=url
    DOMAIN=my.domain.url
```

EXAMPLES
========
```python
>>> include mldap
>>> ad = mldap.mldap()
>>> ad.exists('some-username')
True

>>> help(ad)
```
