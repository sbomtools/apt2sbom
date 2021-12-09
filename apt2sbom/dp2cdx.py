#!python

# import json
from apt.cache import Cache,Package,Version
from apt.package import Record
from socket import gethostname
from datetime import datetime
import re
import json
from .piplist import getpip
from uuid import uuid4

def tocyclonedx(pattern = None,dopip=False):
    s = { }
    pkgs = [ ]
    deps = []

    s["bomFormat"] = "CycloneDX"
    s["specVersion"] = "1.3",
    s["dataLicense"] = "CC0-1.0"
    s["serialNumber"] = "urn:uuid" + str(uuid4())
    s["version"] = 1

    m= {
        "timestamp" : str(re.sub('\..*$','',datetime.now().isoformat())) + 'Z',
        "tools" : [ {
            "vendor" : "Eliot Lear",
            "name" : "apt2sbom",
            } ],
        "component" : {
            "type" : "device",
            "name" : "ubuntu-derived-system",
            "version" : "1"
            }
      }
    s['metadata']= m

    cache=Cache()

    for pkg in cache:
        if not pkg.is_installed:
            continue
        if pattern:
            if not re.match(pattern,pkg.name): 
               continue
        ver = pkg.installed
        r=ver.record
        p = { }
        p['type'] = 'application'
        p["name"]=pkg.name
        v=ver.version
        v=v.replace("~","-")
        v=v.replace(":","-")
        p["bomref"] = pkg.name
        p["version"] = ver.version
        p["supplier"] = { "name" : r['Maintainer'] }
        if not ver.uri == None and not ver.uri == "":
            p['supplier']['url']= [ ver.uri ]
        
        h= []
        try:
            h.append({ "alg" : 'SHA-256',
                       'content' : ver.sha256 })
        except:
            pass
        try:
            h.append({ "alg" : 'SHA-1',
                       'content' : ver.sha1 })
        except:
            pass

        try:
            h.append({ "alg" : 'MD5',
                       'content' : ver.md5 })
        except:
            pass
        
        if not h == []:
            p['hashes'] = h

        if not ver.homepage == '':
            p['externalReferences'] = [ {
                "url" : ver.homepage,
                "type" : "website"
            } ]
        
        if not ver.dependencies == []:
            dep = { "ref" : p["bomref"] }
            dees = []
            
            for d in ver.dependencies:
                tname=re.sub(':any$','',d[0].name)
                if tname in cache and cache[tname].is_installed:
                    dees.append(tname)
                                
            if not dees == []:
                dep["dependsOn"] = dees
                deps.append(dep)
                    
        pkgs.append(p)


    if dopip:
        pips = getpip()
        for pk in pips:
            if pattern:
                if not re.match(pattern,pk['Name']):
                    continue
            p={}
            p["name"]=pk['Name']
            p['type']='application'
            p["version"] = pk['Version']
            p["bomref"] = pk['Name']
            p["supplier"] = {
                "name" + pk['Author']
                }
# + ' <' + pk['Author-email'] + '>'
            try:
                p['externalReferences'] = [ {
                    "url" : pk['homepage'],
                    "type" : "website"
                    }]
            except:
                pass
            pkgs.append(p)

    s['components'] = pkgs
    s['dependencies'] = deps
    return(json.dumps(s))
