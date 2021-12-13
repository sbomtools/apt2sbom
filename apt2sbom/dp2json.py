#!python

# import json
from apt.cache import Cache,Package,Version
from apt.package import Record
from socket import gethostname
from datetime import datetime
import re
import json
from .piplist import getpip

def tojson(pattern = None,dopip=False):
    s = { }
    cinfo = { }
    pkgs = [ ]
    pkgids = [ ]
    deps = {}
    rels = []
    s["spdxVersion"] = "SPDX-2.2"
    s["SPDXID"] = "SPDXRef-DOCUMENT"
    s["dataLicense"] = "CC0-1.0"
    cinfo["creators"] =  [ "Tool: sbomOMatic-ubuntu-1.0" ]
    cinfo["created"] = str(re.sub('\..*$','',datetime.now().isoformat())) + 'Z'

    s['creationInfo']= cinfo

    s["name"] = "dpkg2spdx-" + gethostname()
    s["documentNamespace"] = "https://" + gethostname() + "/.well-known/transparency/sbom"

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
        p["name"]=pkg.name
        v=ver.version
        v=v.replace("~","-")
        v=v.replace(":","-")
        p["SPDXID"] = "SPDXRef-dpkg2spdx." + pkg.name
        pkgids.append(p["SPDXID"])
        p["versionInfo"] = ver.version
        p["filesAnalyzed"] = False
        p["supplier"] = "Organization: " + r['Maintainer']
        p["homepage"]= ver.homepage
        h= []
        try:
            h.append({ "algorithm" : 'SHA256',
                       'checksumValue' : ver.sha256 })
        except:
            pass
        try:
            h.append({ "algorithm" : 'SHA1',
                       'checksumValue' : ver.sha1 })
        except:
            pass

        try:
            h.append({ "algorithm" : 'MD5',
                       'checksumValue' : ver.md5 })
        except:
            pass

        if not h == []:
            p['checksums'] = h

        if not ver.uri == None:
            p["downloadLocation"]= ver.uri
        else:
            p["downloadLocation"]=  "http://spdx.org/rdf/terms#noassertion"
        if not ver.dependencies == []:
            deps[pkg.name] = []
            for d in ver.dependencies:
                tname=re.sub(':any$','',d[0].name)
                if tname in cache and cache[tname].is_installed:
                    deps[pkg.name].append(tname)
            if deps[pkg.name] == []:
                deps.pop(pkg.name)
        p["licenseConcluded"] = "NOASSERTION"
        p["licenseDeclared"] = "NOASSERTION"
        p["copyrightText"] = "NOASSERTION"
        pkgs.append(p)
    if dopip:
        pips = getpip()
        for pk in pips:
            if pattern:
                if not re.match(pattern,pk['Name']):
                    continue
            p={}
            p["name"]=pk['Name']
            p["versionInfo"] = pk['Version']
            p["SPDXID"] = "SPDXRef-dpkg2spdx.pip." + pk['Name']
            p["supplier"] = "Organization: " + pk['Author'] + ' <' + pk['Author-email'] + '>'
            try:
                p["homepage"] = pk['home-page']
            except:
                pass
            p["filesAnalyzed"] = False
            p["downloadLocation"] = "http://spdx.org/rdf/terms#noassertion"
            p["licenseConcluded"] = "NOASSERTION"
#            try:
#                p["licenseDeclared"] = re.sub('[() ]','-',pk['License'])
#            except:
            p["licenseDeclared"] = "NOASSERTION"
            p["copyrightText"] = "NOASSERTION"
            pkgs.append(p)
            pkgids.append(p["SPDXID"])

    s['packages'] = pkgs
    s['documentDescribes'] = pkgids
    for k in deps.keys():
        for d in deps[k]:
                r = { 'spdxElementId' : "SPDXRef-dpkg2spdx." + d,
                      'relatedSpdxElement' : "SPDXRef-dpkg2spdx." + k,
                      'relationshipType' : 'DEPENDENCY_OF'
                      }
                rels.append(r)
    s['relationships']= rels
    return(json.dumps(s))
