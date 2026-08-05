# Contributing

Thank you for helping improve Agent Privacy Gateway.

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
APG_RUN_LOCAL_MODEL_INTEGRATION=1 pytest -m integration \
  tests/test_local_models_integration.py
```

The deterministic E2E harness and live Agent matrix are maintained on the
`dev` branch. Real Agent tests consume external provider capacity and must not
run in ordinary CI. Keep raw artifacts outside the repository and commit only
evidence that has passed the leak assertions and been sanitized.

## Pull requests

- Keep changes focused and explain the security impact.
- Add regression tests for behavior changes.
- Update English and Chinese UI strings together.
- Preserve protocol-native behavior for all three supported upstream formats.
- Do not weaken loopback checks, placeholder validation, audit redaction, or
  provider-key isolation without an explicit threat-model update.
- Confirm that `git diff --check` and the offline checks pass.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
