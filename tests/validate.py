
import json
import sys
from jsonschema import validate


schema_fp=open(sys.argv[1])
sbomfile_fp=open(sys.argv[2])
sbom_json=json.load(sbomfile_fp)
schema_json=json.load(schema_fp)
validate(instance=sbom_json,schema=schema_json)

