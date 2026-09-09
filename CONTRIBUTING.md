# Contributing

Thank you for helping improve PrivacyFlow.

## Before you start

- Search existing issues before opening a new one.
- Open an issue before a large architectural or protocol change.
- Never include real credentials, protected values, private paths, customer
  data, or unsanitized live-Agent transcripts in an issue or pull request.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the offline checks:

```bash
ruff check .
pytest -m 'not integration'
node --check src/gateway/webui/app.js
node --check src/gateway/webui/i18n.js
```

The local-model integration test installs packages and downloads a public test
model. It is opt-in:

```bash
PF_RUN_LOCAL_MODEL_INTEGRATION=1 pytest -m integration \
  tests/test_local_models_integration.py
```

The deterministic E2E harness lives on the default branch and runs in CI.
Real Agent matrices consume external provider capacity and must not run in
ordinary CI. Keep raw artifacts outside the repository and commit only
evidence that has passed the leak assertions and been sanitized. The latest
committed live-agent results remain APG-era; a PrivacyFlow-namespaced live
matrix has not been checked in yet.

## Pull requests

- Keep changes focused and explain the security impact.
- Add regression tests for behavior changes.
- Update English and Chinese UI strings together.
- Preserve protocol-native behavior for all three supported upstream formats.
- Do not weaken loopback checks, placeholder validation, audit redaction, or
  provider-key isolation without an explicit threat-model update.
- Confirm that `git diff --check` and the offline checks pass.
- Add a line under `[Unreleased]` in `CHANGELOG.md` for user-visible changes.

## Releasing

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new version
   heading and bump `version` in `pyproject.toml` to match.
2. Commit, then tag the commit as `vX.Y.Z` and push the tag.
3. The `Release` workflow builds the wheel and sdist, verifies that the tag
   matches the package version, smoke-tests the wheel in a clean environment,
   and creates a GitHub release with the artifacts attached and the matching
   changelog section as notes.

PrivacyFlow is distributed through GitHub releases and `pip install` from the
repository, not through PyPI. The `privacyflow` name on PyPI is not this
project; do not publish there or point users at it.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
