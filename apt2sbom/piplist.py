#!python

import pip_api
import re

# this may be a bit cheeky
from pip_api._call import call

# return an array of global packages.


def getpip():
    pkglist = []
    try:
        p=pip_api.installed_distributions()
    except:
        return []
    
    for d in p.keys():
        args=["show",p[d].name]
        attrs=re.split('\n',call(*args))

        if not attrs == []:
            e={}
            for a in attrs:
                tlv=re.split(': ',a)
                if len(tlv) == 2:
                    e[tlv[0]] = tlv[1]
            pkglist.append(e)
    return pkglist
