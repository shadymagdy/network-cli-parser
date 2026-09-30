"""Turn a whole terminal log (many commands) into one JSON document keyed by command.

    python examples/session_to_json.py tests/data/xr_session.log
"""

import json
import sys

import clijson

text = open(sys.argv[1]).read()
report = {}
for r in clijson.parse_session(text, normalize=True):
    report[r.command] = {"parser": r.parser, "data": r.normalized if r.normalized is not None else r.data}
print(json.dumps(report, indent=2))
