# Copyright (c) 2022, Cisco Systems, Inc. and/or its affiliates.
# All rights reserved.
# See accompanying LICENSE file in apt2sbom distribution.
"""
Routines to convert APT information -> SPDX YAML.
"""

import re
from datetime import datetime
from socket import gethostname
from apt.cache import Cache

def toyaml(pattern = None):
    """
    Function to convert APT information to YAML.
    """
    res="SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT"
    res+="DocumentName: dpkg2spdx-" + gethostname() + "\n"
    res+="DocumentNamespace: https://" + gethostname() + "/.well-known/transparency/sbom\n"
    res+="Creator: Tool: sbomOMatic-ubuntu-1.0\n"
    res+="Created: " + str(re.sub(r'..*$','',datetime.now().isoformat())) + 'Z\n\n'

    cache=Cache()
    deps = {}
    for pkg in cache:
        if not pkg.is_installed:
            continue
        if pattern:
            if not re.match(pattern,pkg.name):
                continue
        ver = pkg.installed
        rec_info=ver.record
        clean_ver = ver.version.replace("[:~]","-")
        res+="SPDXID: SPDXRef-dpkg2spdx." + pkg.name + "." + \
            clean_ver +"\n"
        res+="PackageName: " + pkg.name + "\n"
        res+="PackageVersion: " + clean_ver + "\n"
        res+="FilesAnalyzed: false" + "\n"
        res+="PackageSupplier: Organization: " +  rec_info['Maintainer'] + "\n"
        if not ver.homepage == '':
            res+="PackageHomePage: "+ ver.homepage + "\n"
        try:
            res+="PackageChecksum: SHA256: " + ver.sha256 + "\n"
        except SystemError:
            pass
        if ver.uri and not ver.uri == "":
            res+="PackageDownloadLocation: " + str(ver.uri) + "\n"
        else:
            res+="PackageDownloadLocation: NOASSERTION\n"
        res+="PackageLicenseConcluded: NOASSERTION" + "\n"
        res+="PackageLicenseDeclared: NOASSERTION" + "\n"
        res+="PackageCopyrightText: NOASSERTION" + "\n\n"
        if not ver.dependencies == []:
            deps[pkg.name] = []
            for dep in ver.dependencies:
                tname=re.sub(':any$','',dep[0].name)
                if tname in cache and cache[tname].is_installed:
                    deps[pkg.name].append(tname)
            if deps[pkg.name] == []:
                deps.pop(pkg.name)
    for k in deps:
        for dep in deps[k]:
            res += "Relationship: " + "SPDXRef-dpkg2spdx." + k + \
               " DEPENDS_ON " + "SPDXRef-dpkg2spdx." + dep + "\n"
    res+="\n"
    return res
