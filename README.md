# Agent Privacy Gateway

[![CI](https://github.com/zzhtx258/Agent-Privacy-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/zzhtx258/Agent-Privacy-Gateway/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Agent Privacy Gateway (APG) is a local privacy proxy for cloud coding agents and
LLM clients. It detects sensitive values before a request leaves the machine,
replaces them with signed placeholders, and restores authorized placeholders
only at local user or tool sinks.

> [!IMPORTANT]
> APG is pre-1.0 software. Review the [security model](#security-model) and test
> it with your own workflows before using it with production credentials.

## Why APG

- OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages are separate
  native upstream formats. APG never translates requests, responses, streams,
  tool calls, or errors between them.
- Provider credentials stay in a mode-`0600` local configuration and are not
  returned by the management API.
- Deterministic credential, personal-information, and local-path detectors run
  locally. Optional small models run in an isolated managed environment.
- Signed, session-bound placeholders can be restored transparently in local
  answers and structured tool arguments.
- The management UI supports multiple named upstream configurations, detector
  dry runs, protected-value review, audit review, and local-model management.

## Quick start

Requirements:

- Python 3.11 or newer
- macOS, Linux, or Windows

Install from a checkout:

```bash
git clone https://github.com/zzhtx258/Agent-Privacy-Gateway.git
cd Agent-Privacy-Gateway
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
apg
```

The first start creates `.apg/launcher.json`, a random local Agent API key, and
a signing secret. Open the printed loopback WebUI URL, add an upstream
configuration, and enable APG with the master switch.

Point clients at one of the local endpoints:

| Client format | Base URL |
| --- | --- |
| OpenAI Chat Completions | `http://127.0.0.1:8765/v1` |
| OpenAI Responses | `http://127.0.0.1:8765/v1` |
| Anthropic Messages | `http://127.0.0.1:8765` |

Use the local Agent API key shown in the WebUI. Select the model in the Agent or
client itself; APG deliberately does not own Agent model selection. The client
endpoint must match the active upstream format exactly.

The repository-level `./apg` wrapper is also available for development
checkouts. Installed environments should use the `apg` console command.

## Configuration

The WebUI is the recommended configuration path. Advanced deployments can use
environment variables:

```bash
export APG_UPSTREAM_API_KEY='provider-key'
export APG_UPSTREAM_BASE_URL='https://api.openai.com'
export APG_UPSTREAM_PROTOCOL='openai_chat_completions'
export APG_SIGNING_SECRET='long-random-local-secret'
export APG_LOCAL_API_KEYS='long-random-agent-key'
export APG_PORT=8765
```

`APG_UPSTREAM_PROTOCOL` accepts:

- `openai_chat_completions`
- `openai_responses`
- `anthropic_messages`

Useful optional settings:

```bash
export APG_ADMIN_ENABLED=true
export APG_PII_MODE='pseudonymize'  # pseudonymize, redact, or allow
export APG_GC_INTERVAL_SECONDS=60
```

See [`config/example_policy.yaml`](config/example_policy.yaml) for policy
settings.

## How protection works

Input:

```text
Email alice@example.test, path /Users/alice/private/project, key sk-example-...
```

Model-visible form:

```text
Email <APG:v1:pii:...>, path /workspace/project-hash, key <APG:v1:secret:...>
```

1. APG detects a value in local request content.
2. It stores the mapping locally and sends a signed placeholder or path alias
   upstream.
3. If the model needs the value, it emits the placeholder unchanged.
4. APG verifies the signature, session, workspace, mapping state, and sink.
5. APG restores the value only in the local user-facing response or decoded
   structured tool argument.

Raw values are never restored into upstream/model-visible traffic. Invalid,
altered, expired, revoked, or cross-session placeholders fail closed.

## Detection

The default pipeline combines:

- deterministic credential and key rules;
- deterministic personal-information rules;
- local-path detection;
- optional entropy/context heuristics;
- optional local model detection.

Risk levels are audit metadata; they do not change how protected data is
replaced. Detector modules can choose fail-open or fail-close behavior under
advanced settings. Enforcement remains in the policy, mapping, placeholder, and
materialization layers rather than in model confidence scores.

The WebUI can dry-run any saved detector configuration without activating it.
The result highlights each finding and identifies the module that produced it.

### Local models

The Local model management page accepts a Hugging Face repository/URL or an
existing local directory. **Add and prepare** performs:

```text
inspect → prepare isolated runtime → download → real inference verification
```

APG does not install PyTorch into its own environment. It creates a versioned
runtime under `.apg/runtimes/`, stores managed model data under `.apg/models/`,
and communicates with a local worker over private JSON Lines. Remote custom code
is disabled. Local directories are read-only from APG's perspective.

## Management and storage

The management API and WebUI have no application-layer authentication. They
must remain loopback-only. Never publish port `8765`, reverse-proxy the
management routes, or bind APG to an untrusted network.

Local state defaults to `.apg/`:

| Path | Contents |
| --- | --- |
| `launcher.json` | named upstream profiles, provider keys, local Agent key |
| `apg.sqlite3` | protected-value mappings and operation records |
| `detector-control.json` | detector configurations |
| `local-models.json` | local-model catalog and validation state |
| `models/` | APG-managed Hugging Face cache |
| `runtimes/` | isolated model runtime |

Secret-bearing files are created with restrictive permissions where supported.
Place the state directory on encrypted storage and restrict access to the APG
process user.

## Security model

APG protects values in traffic that actually passes through APG. It does not:

- sandbox an Agent or approve its tools;
- stop a local process from reading files directly;
- control destinations contacted by locally executed tools;
- replace a secrets manager, endpoint security product, or network policy;
- make an untrusted management endpoint safe.

A prompt-injected model can request a local tool call that sends a materialized
secret to an attacker. The Agent harness must gate tool execution and outbound
destinations. Read the full [design and threat model](docs/design.md) and
[WebUI security notes](docs/webui.md). Report vulnerabilities according to
[`SECURITY.md`](SECURITY.md).

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -m 'not integration'
node --check src/gateway/webui/app.js
node --check src/gateway/webui/i18n.js
ruff check .
```

The deterministic Agent harness is offline:

```bash
python -m e2e_agent_tests.scripts.run_all
```

Real Agent validation is opt-in and consumes provider capacity. Because APG
does not convert protocols, run each Agent separately with a matching saved
upstream profile:

```bash
python -m e2e_agent_tests.scripts.run_live_agents \
  --launcher-config .apg/openai-chat-launcher.json \
  --agents opencode \
  --concurrency 4

python -m e2e_agent_tests.scripts.run_live_agents \
  --launcher-config .apg/anthropic-launcher.json \
  --agents claude \
  --concurrency 4
```

Use `--agents claude`, `--agents opencode`, `--model MODEL`, and
`--concurrency N` to narrow a run. The runner asserts upstream, workspace,
audit, final-answer, and provider-key leak boundaries. Checked-in evidence is
sanitized; see:

- [`docs/live_validation_results.md`](docs/live_validation_results.md)
- [`docs/live_agent_scenarios.html`](docs/live_agent_scenarios.html)
- [`docs/e2e_test_plan.md`](docs/e2e_test_plan.md)

Networked local-model integration is excluded from normal tests. Run it only
when downloads are intentional:

```bash
APG_RUN_LOCAL_MODEL_INTEGRATION=1 pytest -m integration \
  tests/test_local_models_integration.py
```

## Project layout

- [`src/gateway/`](src/gateway/) — gateway, detection, storage, proxy, and UI
- [`tests/`](tests/) — unit and API regression tests
- [`e2e_agent_tests/`](e2e_agent_tests/) — deterministic and live Agent matrix
- [`docs/`](docs/) — design, operations, validation, and implementation notes
- [`examples/`](examples/) — minimal client examples

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and
follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Please open an issue
before large architectural changes.

## License

Licensed under the [Apache License 2.0](LICENSE). Bundled third-party notices are
kept under [`docs/vendor/`](docs/vendor/).
