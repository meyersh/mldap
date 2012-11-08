#!/usr/bin/env python
# Some tests for MLDAP (about time)
#
import mldap
import ldap
import unittest

class TestPaging(unittest.TestCase):
    def setUp(self):
        self.ad = mldap.mldap()

    def test_listou(self):
        
        results = self.ad.listou()
        self.assertIsNotNone(results)
        self.assertIsInstance(results,list)

        username = self.ad.LDAP_USERNAME.split('@')[0]
        self.assertIsInstance(results[0], str)
        self.assertIn(username, results)
        

if __name__ == '__main__':
    unittest.main()
