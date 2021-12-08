from flask import Flask,Response, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from apt2sbom.dp2yaml import toyaml
from apt2sbom.dp2json import tojson
import json, requests

with open("/etc/sbom.users","r") as f:
   users = json.load(f)

app = Flask(__name__)
app.url_map.strict_slashes = False
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username in users and \
       ( users.get(username) == password):
        return username

@app.route('/',methods=['GET'])
@auth.login_required
def return_sbom():
   if ( "application/json" in request.accept_mimetypes or
        "application/spdx+json" in request.accept_mimetypes ):
      return Response(tojson(),mimetype="application/spdx+json")
   return Response(toyaml(),mimetype="text/spdx")


@app.route('/<pattern>',methods=['GET'])
@auth.login_required
def search_sbom(pattern = None):
   if  pattern is None:
      return ("Error: must have pattern", 400)
   pattern = '.*' + pattern + '.*'
   if ( "application/json" in request.accept_mimetypes or
	"application/spdx+json" in request.accept_mimetypes ):
      return Response(tojson(pattern),mimetype="application/spdx+json")
   return Response(toyaml(pattern),mimetype="text/spdx")
