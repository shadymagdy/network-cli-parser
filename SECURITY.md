# Security policy

## Supported versions

Security fixes are released for the latest minor version of clijson.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub security advisories](https://github.com/shadymagdy/network-cli-parser/security/advisories/new) instead.
Include a description, the affected version and, if possible, a minimal input that reproduces the problem.

You can expect an acknowledgement within a few days. A fix or mitigation plan will follow once the report is
confirmed.

## Scope notes

* clijson parses untrusted text. Inputs that crash a parser, hang it (catastrophic regex backtracking) or exhaust
  memory are in scope. The test suite fuzzes every parser against every capture to guard against this.
* `clijson serve` and `clijson mcp --transport http` have no authentication. They bind to `127.0.0.1` by
  default. Put them behind a reverse proxy or VPN before exposing them to a network.
* Releases are published from GitHub Actions with PyPI trusted publishing and carry build provenance
  attestations (`gh attestation verify <file> --repo shadymagdy/network-cli-parser`).
