# Contributing

Thanks for helping. Real device outputs are the most valuable contribution. Every capture you add
makes the parsers more robust for everyone.

## Setup

```bash
git clone https://github.com/shadymagdy/network-cli-parser && cd network-cli-parser
pip install -e ".[dev]"
pytest
```

## Improving or adding a parser

1. Capture the output, then **sanitise** it: replace hostnames, public IPs, serial numbers and descriptions
   that identify customers.
2. Look at what happens today: `clijson parse capture.txt -p <platform> -c "<command>" -m`.
3. Write or fix the parser in `src/clijson/parsers/<platform>/`. See [docs/writing-parsers.md](docs/writing-parsers.md).
4. Add a fixture: `python scripts/fixture.py add capture.txt -p <platform> -c "<command>" --name <model_or_release>`,
   then **review the JSON**.
5. Run `pytest`, `ruff check src tests scripts` and `python scripts/gen_docs.py`.

Guidelines:

* Keep vendor field names (snake_case) in the native output. Put cross-vendor mapping in `normalize()`.
* Prefer flat lists of records with context fields (`vrf`, `instance`, …) over deep nesting.
* Never let one line's regex span into the next. Use `match_lines` or line loops.
* Keep values that are identifiers as strings: asdot ASNs, interface names, zero-padded IDs.
* If a parser changes output for existing fixtures, say so in the PR and in `CHANGELOG.md`.

## Reporting a parsing problem

Open an issue with the platform, OS release, the exact command and a sanitised capture. Include what you
expected to get.
