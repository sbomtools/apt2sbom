# Copyright (c) 2022, Cisco Systems, Inc. and/or its affiliates.
# All rights reserved.
# See accompanying LICENSE file in apt2sbom distribution.

"""
Routines to call from werkzeug to enable simple sbom web service.
"""

import json
from os import getuid
from flask import Flask,Response, request
from flask_httpauth import HTTPBasicAuth
from apt2sbom.dp2yaml import toyaml
from apt2sbom.dp2json import tojson
from apt2sbom.dp2cdx import tocyclonedx
from apt2sbom.readconf import readconf

conf=readconf("/etc/sbom.conf")

if getuid() == 0:
    raise RuntimeError("Not running as root")


if 'do_auth' in conf and conf['do_auth'] is True:
    if 'passwd_file' not in conf:
        raise ValueError('passwd_file')

    try:
        with open(conf['passwd_file'],"r",encoding="utf-8") as f:
            users = json.load(f)
    except OSError as pw_error:
        print("unable to load passwd file")
        exit(-1)

app = Flask(__name__)
app.url_map.strict_slashes = False
auth = HTTPBasicAuth()

if 'do_auth' in conf and conf['do_auth']:
    @auth.verify_password
    def verify_password(username, password):
        """ Basic password check """
        if username in users and \
           ( users.get(username) == password):
            return username
        return None

def get_sbom(pattern=None):
    """
    generate SBOM once we are authenticated.
    """
    if 'pre_gen' in conf and conf['pre_gen']:
        if 'sbom_type' in conf:
            sbom_mime=conf['sbom_type']
        else:
            raise ValueError("sbom_type required and not set.")
        try:
            with open(conf['pre_gen'],"r",encoding="utf-8") as sbom_fp:
                sbom=sbom_fp.read()
            return Response(sbom,mimetype=sbom_mime)
        except OSError as sbom_error:
            return Response(str(sbom_error),400)

    if ( "application/json" in request.accept_mimetypes or
         "application/spdx+json" in request.accept_mimetypes ):
        return Response(tojson(pattern),mimetype="application/spdx+json")
    if "application/vnd.cyclonedx+json" in request.accept_mimetypes:
        return Response(tocyclonedx(pattern),mimetype="application/vnd.cyclonedx+json")
    return Response(toyaml(pattern),mimetype="text/spdx")


if "do_auth" in conf and conf['do_auth']:
    @app.route('/',methods=['GET'])
    @auth.login_required
    def return_sbom():
        """ Return an SBOM with no params"""
        return get_sbom(None)

    @app.route('/<pattern>',methods=['GET'])
    @auth.login_required
    def search_sbom(pattern = None):
        """ return sbom with a search param """
        pattern = '.*' + pattern + '.*'
        return get_sbom(pattern)

else:
    @app.route('/',methods=['GET'])
    def return_sbom():
        """ Return an SBOM with no params"""
        return get_sbom(None)

    @app.route('/<pattern>',methods=['GET'])
    def search_sbom(pattern = None):
        """ return sbom with a search param """
        pattern = '.*' + pattern + '.*'
        return get_sbom(pattern)
