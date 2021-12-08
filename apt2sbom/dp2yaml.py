from apt.cache import Cache,Package,Version
from apt.package import Record
from socket import gethostname
from datetime import datetime
import re

def toyaml(pattern = None):
   res="SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT"
   res+="DocumentName: dpkg2spdx-" + gethostname() + "\n"
   res+="DocumentNamespace: https://" + gethostname() + "/.well-known/transparency/sbom\n"
   res+="Creator: Tool: sbomOMatic-ubuntu-1.0\n"
   res+="Created: " + str(re.sub('\..*$','',datetime.now().isoformat())) + 'Z\n\n'

   cache=Cache()
   deps = {}
   for pkg in cache:
      if not pkg.is_installed:
         continue
      if pattern:
         if not re.match(pattern,pkg.name):
            continue
      ver = pkg.installed
      r=ver.record
      v=ver.version.replace("~","-")
      v=v.replace(":","-")
      res+="SPDXID: SPDXRef-dpkg2spdx." + pkg.name + "." + v +"\n"
      res+="PackageName: " + pkg.name + "\n"
      res+="PackageVersion: " + ver.version + "\n"
      res+="FilesAnalyzed: false" + "\n"
      res+="PackageSupplier: Organization: " +  r['Maintainer'] + "\n"
      if not ver.homepage == '':
         res+="PackageHomePage: "+ ver.homepage + "\n"
      try:
         res+="PackageChecksum: SHA256: " + ver.sha256 + "\n"
      except:
         pass
      try:
         res+="PackageDownloadLocation: " + ver.uri + "\n"
      except:
         res+="PackageDownloadLocation: NOASSERTION\n"
      res+="PackageLicenseConcluded: NOASSERTION" + "\n"
      res+="PackageLicenseDeclared: NOASSERTION" + "\n"
      res+="PackageCopyrightText: NOASSERTION" + "\n\n"
      if not ver.dependencies == []:
         deps[pkg.name] = []
         for d in ver.dependencies:
            tname=re.sub(':any$','',d[0].name)
            if tname in cache and cache[tname].is_installed:
               deps[pkg.name].append(tname)
         if deps[pkg.name] == []:
            deps.pop(pkg.name)
   for k in deps.keys():
      for d in deps[k]:
         res += "Relationship: " + "SPDXRef-dpkg2spdx." + k + \
            " DEPENDS_ON " + "SPDXRef-dpkg2spdx." + d + "\n"
   res+="\n"
   return res
