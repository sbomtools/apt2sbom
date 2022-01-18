#!python
"""
Routines to read configuration.  Only necessary for web access (not
cli).

Current values supported with default values (if any):

   do_auth: True,  # otherwise don't auth
   passwd_file: "/etc/sbom.users",  # where to find the passwds
   include_pip: False, # pip results take a long time
   pregen_file: None # only open and read this file; otherwise gen.

"""

import json

def readconf(conffile):
    """
    read the configuration file, and return configuration elements in
    a dict.
    """

    try:
        with open(conffile,"r",encoding="utf-8") as conf_fp:
            conf=json.load(conf_fp)
    except OSError as j_error:
        print(f'Error: {j_error}')
        conf={}
    return conf

