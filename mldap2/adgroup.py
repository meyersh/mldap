class ADgroup(object):
    def __init__(self, groupname, dn, ad_obj=None):
        self.__dict__ = {'dn': dn, 'name': groupname, 'members': list()}
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
