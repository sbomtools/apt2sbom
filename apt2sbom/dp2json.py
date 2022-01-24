#!python
# Copyright (c) 2022, Cisco Systems, Inc. and/or its affiliates.
# All rights reserved.
# See accompanying LICENSE file in apt2sbom distribution.
"""
Convert apt and pip information to SPDX JSON format.
"""

# import json
from socket import gethostname
from datetime import datetime
import re
import json
from apt.cache import Cache
from .piplist import getpip

def tojson(pattern = None,dopip=False):
    """
    Convert APT information to SPDX JSON.
    """

    sbom = { }
    cinfo = { }
    pkgs = [ ]
    pkgids = [ ]
    deps = {}
    rels = []
    sbom = {
        "spdxVersion" : "SPDX-2.2",
        "SPDXID" : "SPDXRef-DOCUMENT",
        "dataLicense" : "CC0-1.0",
        "name" : "dpkg2spdx-" + gethostname(),
        "documentNamespace" : "https://" + gethostname() + "/.well-known/transparency/sbom"
    }
    cinfo["creators"] =  [ "Tool: apt2sbom-ubuntu-1.0" ]
    cinfo["created"] = str(re.sub(r'..*$','',datetime.now().isoformat())) + 'Z'

    sbom['creationInfo']= cinfo


    cache=Cache()

    for pkg in cache:
        if not pkg.is_installed:
            continue
        if pattern:
            if not re.match(pattern,pkg.name):
                continue
        ver = pkg.installed
        rec_info=ver.record
        pack = { }
        pack["name"]=pkg.name
        pack["SPDXID"] = "SPDXRef-dpkg2spdx." + pkg.name
        pkgids.append(pack["SPDXID"])
        pack["versionInfo"] = re.sub("[:~]","-",ver.version)
        pack["filesAnalyzed"] = False
        pack["supplier"] = "Organization: " + rec_info['Maintainer']
        pack["homepage"]= ver.homepage
        hashes= []
        try:
            hashes.append({ "algorithm" : 'SHA256',
                       'checksumValue' : ver.sha256 })
        except SystemError:
            pass

        try:
            hashes.append({ "algorithm" : 'SHA1',
                       'checksumValue' : ver.sha1 })
        except SystemError:
            pass

        try:
            hashes.append({ "algorithm" : 'MD5',
                       'checksumValue' : ver.md5 })
        except SystemError:
            pass

        if hashes:
            pack['checksums'] = hashes

        if ver.uri:
            pack["downloadLocation"]= ver.uri
        else:
            pack["downloadLocation"]=  "http://spdx.org/rdf/terms#noassertion"
        if ver.dependencies:
            deps[pkg.name] = []
            for dep in ver.dependencies:
                tname=re.sub(':any$','',dep[0].name)
                if tname in cache and cache[tname].is_installed:
                    deps[pkg.name].append(tname)
            if deps[pkg.name] == []:
                deps.pop(pkg.name)
        pack["licenseConcluded"] = "NOASSERTION"
        pack["licenseDeclared"] = "NOASSERTION"
        pack["copyrightText"] = "NOASSERTION"
        pkgs.append(pack)
    if dopip:
        pips = getpip()
        for pip in pips:
            if pattern:
                if not re.match(pattern,pip['Name']):
                    continue
            pack={}
            pack["name"]=pip['Name']
            pack["versionInfo"] = pip['Version']
            pack["SPDXID"] = "SPDXRef-dpkg2spdx.pip." + pip['Name']
            pack["supplier"] = "Organization: " + pip['Author'] + ' <'\
                + pip['Author-email'] + '>'
            try:
                pack["homepage"] = pip['home-page']
            except KeyError:
                pass
            pack["filesAnalyzed"] = False
            pack["downloadLocation"] = "http://spdx.org/rdf/terms#noassertion"
            pack["licenseConcluded"] = "NOASSERTION"
            pack["licenseDeclared"] = "NOASSERTION"
            pack["copyrightText"] = "NOASSERTION"
            pkgs.append(pack)
            pkgids.append(pack["SPDXID"])

    sbom['packages'] = pkgs
    sbom['documentDescribes'] = pkgids
    for pname in deps:
        for dep in deps[pname]:
            rec_info = { 'spdxElementId' : "SPDXRef-dpkg2spdx." + dep,
                  'relatedSpdxElement' : "SPDXRef-dpkg2spdx." + pname,
                  'relationshipType' : 'DEPENDENCY_OF'
                 }
            rels.append(rec_info)

    sbom['relationships']= rels
    return json.dumps(sbom)
