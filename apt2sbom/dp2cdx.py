#!python
# Copyright (c) 2022, Cisco Systems, Inc. and/or its affiliates.
# All rights reserved.
# See accompanying LICENSE file in apt2sbom distribution.
"""
routine to convert apt and pip information to CycloneDX.
"""
import re
import json
from uuid import uuid4
from datetime import datetime
from apt.cache import Cache
from .piplist import getpip

def tocyclonedx(pattern = None,dopip=False):
    """
    Routine to convert apt information to CycloneDx.
    """
    pkgs = [ ]
    deps = []

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid4()),
        "version": 1
        }
    meta = {
        "timestamp": re.sub(r'[.].*$','',str(datetime.now().isoformat())) + 'Z',
        "tools" : [ {
            "vendor" : "Eliot Lear",
            "name" : "apt2sbom",
            } ],
        "component" : {
            "type" : "device",
            "name" : "ubuntu-derived-system",
            "version" : "1"
            },
        "licenses" : [ { "license" : {
            "id" : "BSD-3-Clause"
            }
        } ]
      }
    sbom['metadata']= meta

    cache=Cache()

    for pkg in cache:
        if not pkg.is_installed:
            continue
        if pattern:
            if not re.match(pattern,pkg.name):
                continue
        ver = pkg.installed
        pack = { }
        pack['type'] = 'application'
        pack["name"]=pkg.name
        rec_info=ver.record
        pack["bom-ref"] = pkg.name
        pack["version"] = ver.version
        pack["purl"] = "pkg:deb/ubuntu/" + pkg.name + "@" + ver.version +\
            "?arch=" + ver.architecture
        pack["supplier"] = { "name" : rec_info['Maintainer'] }
        if not ver.uri is None and not ver.uri == "":
            pack['supplier']['url']= [ ver.uri ]

        hashes= []
        try:
            hashes.append({ "alg" : 'SHA-256',
                       'content' : ver.sha256 })
        except SystemError:
            pass
        try:
            hashes.append({ "alg" : 'SHA-1',
                       'content' : ver.sha1 })
        except SystemError:
            pass

        try:
            hashes.append({ "alg" : 'MD5',
                       'content' : ver.md5 })
        except SystemError:
            pass

        if hashes:
            pack['hashes'] = hashes

        if ver.homepage != '':
            pack['externalReferences'] = [ {
                "url" : ver.homepage,
                "type" : "website"
            } ]

        if ver.dependencies:
            dep = { "ref" : pack["bom-ref"] }
            dees = []

            for dep_ent in ver.dependencies:
                tname=re.sub(':any$','',dep_ent[0].name)
                if tname in cache and cache[tname].is_installed and\
                   not tname in dees:
                    dees.append(tname)

            if dees:
                dep["dependsOn"] = dees
                deps.append(dep)

        pkgs.append(pack)

    if dopip:
        pips = getpip()
        for pip in pips:
            if pattern:
                if not re.match(pattern,pip['Name']):
                    continue
            pack={}
            pack["name"]=pip["Name"] + ".pip"
            pack['type']="application"
            pack["version"] = pip["Version"]
            pack["purl"] = "pkg:pypi/" + re.sub('_','-',pack["name"].lower()) +\
                "@" + pack["version"]
            pack["bom-ref"] = pack["name"]
            pack["supplier"] = {
                "name" : pip["Author"]
                }
            try:
                pack["externalReferences"] = [ {
                    "url" : pip["homepage"],
                    "type" : "website"
                    }]
            except KeyError:
                pass
            pkgs.append(pack)

    sbom['components'] = pkgs
    sbom['dependencies'] = deps
    return json.dumps(sbom)
