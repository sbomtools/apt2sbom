"""
Routines to call from werkzeug to enable simple sbom web service.
"""

import json
from flask import Flask,Response, request
from flask_httpauth import HTTPBasicAuth
# from werkzeug.security import generate_password_hash, check_password_hash
from apt2sbom.dp2yaml import toyaml
from apt2sbom.dp2json import tojson
from apt2sbom.dp2cdx import tocyclonedx

with open("/etc/sbom.users","r") as f:
    users = json.load(f)

app = Flask(__name__)
app.url_map.strict_slashes = False
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    """ Basic password check """
    if username in users and \
       ( users.get(username) == password):
        return username
    return None

@app.route('/',methods=['GET'])
@auth.login_required
def return_sbom():
    """ Return an SBOM with no params"""
    if ( "application/json" in request.accept_mimetypes or
         "application/spdx+json" in request.accept_mimetypes ):
        return Response(tojson(),mimetype="application/spdx+json")
    if "application/vnd.cyclonedx+json" in request.accept_mimetypes:
        return Response(tocyclonedx(),mimetype="application/vnd.cyclonedx+json")
    return Response(toyaml(),mimetype="text/spdx")


@app.route('/<pattern>',methods=['GET'])
@auth.login_required
def search_sbom(pattern = None):
    """ return sbom with a search param """
    if  pattern is None:
        return ("Error: must have pattern", 400)
    pattern = '.*' + pattern + '.*'
    if ( "application/json" in request.accept_mimetypes or
         "application/spdx+json" in request.accept_mimetypes ):
        return Response(tojson(pattern),mimetype="application/spdx+json")
    if "application/vnd.cyclonedx+json" in request.accept_mimetypes:
        return Response(tocyclonedx(pattern),mimetype="application/vnd.cyclonedx+json")
    return Response(toyaml(pattern),mimetype="text/spdx")
