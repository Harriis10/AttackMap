import json
from attackmap.cli import app
from attackmap.desktop_capabilities import build_capabilities
print(json.dumps(build_capabilities(app)['analyzer_profiles'],indent=2))
