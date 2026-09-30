# Contributing

Thanks for helping. Real device outputs are the most valuable contribution. Every capture you add
makes the parsers more robust for everyone.

## Setup

```bash
git clone https://github.com/shadymagdy/network-cli-parser && cd network-cli-parser
uv sync                      # installs the package + dev tools into .venv from uv.lock
uv run pre-commit install    # lint and format automatically on commit
uv run pytest
```

Don't have uv? `pip install uv`, or see <https://docs.astral.sh/uv/getting-started/installation/>.
Plain pip also works: `pip install -e . pytest pytest-cov PyYAML ruff`.

### Tooling at a glance

| Task | Command |
| --- | --- |
| Run tests | `uv run pytest` (coverage: `uv run pytest --cov`) |
| Lint / format | `uv run ruff check --fix .` / `uv run ruff format .` |
| All hooks | `uv run pre-commit run -a` |
| Build wheel + sdist | `uv build` |
| Add a dependency | `uv add <pkg>` (runtime) or `uv add --group test <pkg>` |
| Test another Python | `uv run --python 3.10 pytest` |

## Improving or adding a parser

1. Capture the output, then **sanitise** it: replace hostnames, public IPs, serial numbers and descriptions
   that identify customers.
2. Look at what happens today: `clijson parse capture.txt -p <platform> -c "<command>" -m`.
3. Write or fix the parser in `src/clijson/parsers/<platform>/`. See [docs/writing-parsers.md](docs/writing-parsers.md).
4. Add a fixture: `python scripts/fixture.py add capture.txt -p <platform> -c "<command>" --name <model_or_release>`,
   then **review the JSON**.
5. Run `uv run pytest`, `uv run pre-commit run -a` and `uv run scripts/gen_docs.py`.

Guidelines:

* Keep vendor field names (snake_case) in the native output. Put cross-vendor mapping in `normalize()`.
* Prefer flat lists of records with context fields (`vrf`, `instance`, …) over deep nesting.
* Never let one line's regex span into the next. Use `match_lines` or line loops.
* Keep values that are identifiers as strings: asdot ASNs, interface names, zero-padded IDs.
* If a parser changes output for existing fixtures, say so in the PR and in `CHANGELOG.md`.

## Commits and pull requests

* Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(junos): parse show ospf database`, `fix(vrp): ...`, `docs: ...`, `build: ...`, `ci: ...`.
* One feature or fix per pull request, with tests and a `CHANGELOG.md` entry under *Unreleased*.
* CI must be green: lint, format, tests on Python 3.10–3.14 (Linux, plus Windows and macOS), generated docs.

## Reporting a parsing problem

Open an issue with the platform, OS release, the exact command and a sanitised capture. Include what you
expected to get.
