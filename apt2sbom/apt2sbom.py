#!python

from apt2sbom import tojson,toyaml,tocyclonedx
import argparse

def cli():
    parser= argparse.ArgumentParser(description="generate SPDX file from APT inventory")
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-j','--json',help="Generate JSON SPDX output", action='store_true')
    group.add_argument('-y','--yaml',help="Generate YAML SPDX output", action='store_true')
    group.add_argument('-c','--cyclonedx',help="Generate CycloneDX JSON output", action='store_true')
    parser.add_argument('-p','--pip',help="Include PIP files",action='store_true')
    args=parser.parse_args()

    
    if args.json:
        out=tojson(dopip=args.pip)
    elif args.yaml:
        out=toyaml()
    else:
        out=tocyclonedx()
    print(out)



