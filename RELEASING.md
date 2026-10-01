# Releasing

Releases are fully automated by [`.github/workflows/release.yml`](.github/workflows/release.yml).

1. Move the *Unreleased* entries in `CHANGELOG.md` under a new `## X.Y.Z` heading.
2. Bump the version: `uv version X.Y.Z` (this updates `pyproject.toml` and `uv.lock`).
3. Merge that change to `main`, then tag it: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The workflow then:

* checks that the tag matches the package version
* builds the sdist and wheel with `uv build` and smoke-tests the wheel
* signs build provenance attestations
* publishes to PyPI with **trusted publishing** (OIDC, so no API token is stored anywhere)
* creates the GitHub release, attaching the distributions and using the changelog section as release notes

## One-time setup

* **PyPI:** add a trusted publisher for project `clijson` at
  <https://pypi.org/manage/account/publishing/>. Use owner `shadymagdy`, repository `network-cli-parser`,
  workflow `release.yml` and environment `pypi`.
* **GitHub:** create the `pypi` environment (Settings → Environments). Add required reviewers if you want a
  manual approval before each publish.
* **Docs:** set Settings → Pages → Source to **GitHub Actions** so the Docs workflow can deploy the site.
