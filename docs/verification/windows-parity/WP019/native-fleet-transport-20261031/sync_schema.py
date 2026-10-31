import json
from pathlib import Path
from attackmap.desktop_fleet import FleetRunRequest
schema=FleetRunRequest.model_json_schema()
schema['$schema']='https://json-schema.org/draft/2020-12/schema'
Path('schemas/run-fleet-request.schema.json').write_text(json.dumps(schema,indent=2)+'\n',encoding='utf-8')
