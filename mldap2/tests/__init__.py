#!/usr/bin/env python
# Testing tests for mldap
# Note that these do create and delete users (named below).
# Shaun Meyer, Nov 2012

import ldap
import mldap
import unittest

class TestUserDeletionAndCreation(unittest.TestCase):
    test_username = "mldap_unittest_user"
    test_groupname = "mldap_unittest_group"

    def setUp(self):
        self.ad = mldap.mldap()

        self.ad.create(self.test_username, 
                       self.test_username,
                       self.ad.LDAP_BASE)

        self.ad.create_group(self.test_groupname, self.ad.LDAP_BASE)

    def tearDown(self):
        self.ad.delete_user(self.test_username)
        self.ad.delete_user(self.test_groupname)
        self.ad.disconnect()


    ''' Not sure why, but we seem to have to hang up and reconnect for
        AD to show a deleted user when using the exists()
        function.'''
    def test_deleteGroup(self):
        self.ad.delete_user(self.test_groupname)
        self.ad.disconnect()
        self.ad.connect()
        self.assertFalse(self.ad.exists(self.test_groupname))

    def test_deleteUser(self):
        self.ad.delete_user(self.test_username)
        self.ad.disconnect()
        self.ad.connect()
        self.assertFalse(self.ad.exists(self.test_username))


class TestMldap(unittest.TestCase):
    def setUp(self):
        self.ad = mldap.mldap()

    def tearDown(self):
        self.ad.disconnect()

    def test_connect(self):
        self.assertTrue(self.ad.alive())

    def test_disconnect(self):
        self.ad.disconnect()
        self.assertFalse(self.ad.alive())

    def test_exists(self):
        username = self.ad.LDAP_USERNAME.split('@')[0]
        self.assertTrue(self.ad.exists(username))

    def test_listou(self):
        
        results = self.ad.listou()
        self.assertIsNotNone(results)
        self.assertIsInstance(results,list)

        username = self.ad.LDAP_USERNAME.split('@')[0]
        self.assertIsInstance(results[0], str)
        self.assertIn(username, results)
        

if __name__ == '__main__':
    unittest.main()
