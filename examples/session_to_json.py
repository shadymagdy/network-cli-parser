"""Turn a whole terminal log (many commands) into one JSON document keyed by command.

python examples/session_to_json.py tests/data/xr_session.log
"""

import json
import sys
from pathlib import Path

import clijson

text = Path(sys.argv[1]).read_text()
report = {}
for r in clijson.parse_session(text, normalize=True):
    report[r.command] = {"parser": r.parser, "data": r.normalized if r.normalized is not None else r.data}
print(json.dumps(report, indent=2))
