from flask import Flask,Response, request
import json, requests

application = Flask(__name__)
application.url_map.strict_slashes = False

@application.route('/',methods=['POST'])
def return_vis():
   if 'sbfile' in request.files:
      file=request.files['sbfile']
      sbom=json.load(file.stream)
      print(sbom)

