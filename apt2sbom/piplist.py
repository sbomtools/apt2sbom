#!python
"""
Routines to generate lists of python modules installed.
"""

import re
import pip_api
from pip_api._call import call

# return an array of global packages.


def getpip():
    """
    Generate a pip package list.
    """
    pkglist = []
    try:
        pip=pip_api.installed_distributions()
    except SystemError:
        return []

    for dep in pip:
        args=["show",pip[dep].name]
        attrs=re.split('\n',call(*args))

        if not attrs == []:
            entry={}
            for attr in attrs:
                tlv=re.split(': ',attr)
                if len(tlv) == 2:
                    entry[tlv[0]] = tlv[1]
            pkglist.append(entry)
    return pkglist
