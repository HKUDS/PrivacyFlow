<p align="center">
  <img src="assets/branding/apg-icon-robot-shield-v2.png" width="128" alt="Agent Privacy Gateway robot shield logo">
</p>

<h1 align="center">Agent Privacy Gateway</h1>

<p align="center">
  <strong>English</strong> · <a href="README_zh.md">简体中文</a>
</p>

<p align="center"><strong>Keep secrets local. Keep agents working.</strong></p>

<p align="center">
  A local privacy boundary for agents that use cloud LLMs.<br>
  Detect sensitive values, replace them before upload, and restore them only at authorized local sinks.
</p>

<p align="center">
  <a href="https://github.com/zzhtx258/Agent-Privacy-Gateway/actions/workflows/ci.yml"><img src="https://github.com/zzhtx258/Agent-Privacy-Gateway/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11 or newer"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-4C7A64" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/Status-Alpha-C47A19" alt="Alpha status">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-how-it-works">How It Works</a> ·
  <a href="#-supported-api-formats">API Formats</a> ·
  <a href="#-security-boundary">Security</a> ·
  <a href="#-documentation">Docs</a>
</p>

## Why APG?

Coding agents routinely encounter API keys, passwords, personal information,
private paths, and other sensitive values in `.env` files, logs, configuration,
source code, and tool arguments. Sending those values directly to a cloud model
means trusting every provider and intermediary that handles the request. Data
policies vary; some services may retain or reuse requests for model improvement
or training. Unofficial or personal API relays make retention, access, and reuse
even harder to assess.

### What providers say

Data use depends on the product, account type, and privacy settings. On several
consumer services, model-improvement data use remains enabled until the user
turns it off; some safety-review and feedback exceptions still apply after an
opt-out. The providers' own documentation also warns users not to submit
sensitive or confidential information.[^provider-defaults]

| Provider | Official policy |
| --- | --- |
| OpenAI | **ChatGPT and Codex content may be used for training unless the user opts out.** OpenAI also says not to share sensitive information in conversations. [Data-usage policy](https://help.openai.com/en/articles/5722486-api-data-usage-policies) · [ChatGPT privacy guidance](https://help.openai.com/en/articles/6783457-chatgpt-privacy-and-data-security) |
| Anthropic | Claude consumer chats and coding sessions may be used when Model Improvement is enabled, feedback is submitted, or a conversation is flagged for safety review; flagged conversations may still be used for internal safety-model training after the general setting is disabled. Anthropic explicitly says: **“We encourage our users not to use our products and services to process personal data.”** [Consumer policy](https://privacy.claude.com/en/articles/10023555-how-do-you-use-personal-data-in-model-training) · [Commercial policy](https://privacy.claude.com/en/articles/7996885-how-do-you-use-personal-data-in-model-training) |
| Google | **When Gemini Keep Activity is on, chats, files, screens, and photos may be used to improve services, including training generative AI models, with some data reviewed by humans.** Google warns users not to enter confidential information they would not want a reviewer to see or Google to use for improvement. Turning Keep Activity off prevents future chats from being used for general model training unless feedback is submitted, though chats are still retained for 72 hours for service and safety purposes. [Gemini Apps Privacy Hub](https://support.google.com/gemini/answer/13594961?hl=en) |
| DeepSeek | DeepSeek's privacy policy permits operational and statistical analysis of dialogue content to improve algorithmic models, service intelligence, and understanding of user input. Its user agreement separately tells users **not to enter their own or other people's sensitive personal information**; continuing to use the service constitutes acceptance of the policy rather than a separate training opt-in. [Privacy policy](https://platform.deepseek.com/downloads/DeepSeek%20Privacy%20Policy.pdf) · [User agreement](https://platform.deepseek.com/downloads/DeepSeek%20User%20Agreement.pdf) |

These policies do not mean that every provider trains on every request.
But the providers' own warnings make the practical boundary clear: users should
not assume that a cloud LLM is an appropriate place for plaintext personal data
or secrets. APG enforces that boundary locally instead of relying on every user,
agent, setting, and intermediary to handle sensitive values correctly.

### What users have reported

The following public reports have not been confirmed by the providers and do
not independently prove cross-user data leakage. Unexpected content may also
result from hallucination, context contamination, client bugs, or tool input.
They nevertheless illustrate a practical problem: once sensitive data is sent
upstream, users lose control over which systems process it and whether it might
reappear under unexpected conditions.

| Platform | Public report |
| --- | --- |
| Claude | After asking Claude to organize local files and run a Git command, a user received an unrelated comparison of layoff candidates containing roles, salaries, and skills. [View the original post](https://x.com/manateelazycat/status/2076933787217428652) |
| Claude Code | A user reported that unrelated production-server connection details and credentials appeared in a session, after which the Agent connected to the server and modified a third-party database. [View the issue](https://github.com/anthropics/claude-code/issues/72274) |
| ChatGPT | Multiple users reported receiving responses unrelated to files they had uploaded. One response allegedly contained a document uploaded by a local lawyer. [View the discussion](https://news.ycombinator.com/item?id=43615756) |
| Gemini | After uploading audio for transcription, a user received an unrelated business-meeting transcript containing names, corporate email addresses, contracts, and document links. The poster said some of the people and details could be verified. [View the original post](https://www.reddit.com/r/GeminiAI/comments/1v8700z/gemini_gave_me_someone_elses_transcript/) |

APG does not need to assume that every anomaly is a data breach. It replaces
sensitive values before a request leaves the device. If an upstream service
experiences incorrect routing, logging, context contamination, or another
unexpected failure, it sees placeholders rather than the user's API keys,
passwords, or personal information.

Exposing a secret can also interrupt the task itself. A safety-aligned model may
warn the user to revoke a credential, refuse to continue, or avoid using the
value—even when the intended operation is legitimate. The user is then forced
to replace, paste, or manage sensitive values manually, adding friction and
more human-in-the-loop work.

APG keeps the literal value local and gives the model a stable placeholder
instead. The model only needs to know that a secret exists and where it should
be used; it rarely needs to know the secret itself. APG verifies and restores
the original value only at an authorized local destination, so the task can
continue without directly exposing sensitive data to the cloud.

| Detect locally | Protect before upload | Restore locally |
| --- | --- | --- |
| Credentials, PII, local paths, and high-entropy values | Signed placeholders and stable path aliases replace raw values | Verified values reappear in local answers and structured tool arguments |

### What makes APG different

- **Transparent protection** — the model works with stable placeholders; the
  user receives authorized values back without manually decoding them.
- **Local control plane** — provider credentials, protected-value mappings,
  detector configuration, audit records, and optional models stay on the
  machine.
- **Defense against placeholder spoofing** — materialization checks signature,
  session, workspace, mapping state, expiry, revocation, and sink.
- **Inspectable behavior** — dry-run detectors, review protected mappings, and
  audit every replacement and restoration without storing raw values in logs.

## 🛡️ How it works

APG handles both directions locally. Before a request leaves the device, it
detects sensitive values and replaces them with signed placeholders or stable
path aliases. When the model response returns, APG verifies those placeholders
and restores the original values only in authorized local responses or
structured tool arguments. The cloud model only works with the placeholders.

Given this local input:

```text
Email alice@example.test, open /Users/alice/private/project,
and use key sk-example-not-a-real-key.
```

the model sees:

```text
Email <APG:v1:pii:...>, open /workspace/project-hash,
and use key <APG:v1:secret:...>.
```

After the model returns the placeholders, the authorized local result is:

```text
Email alice@example.test, open /Users/alice/private/project,
and use key sk-example-not-a-real-key.
```

If the model needs a protected value, it keeps the placeholder unchanged. APG
verifies the placeholder and restores the original only in the authorized local
response or decoded structured tool argument. Raw values are never restored
into upstream/model-visible traffic.

## ⚡ Quick Start

### 1. Install

Requirements: Python 3.11 or newer on macOS, Linux, or Windows.

```bash
git clone https://github.com/zzhtx258/Agent-Privacy-Gateway.git
cd Agent-Privacy-Gateway

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, activate the environment with
`.venv\Scripts\Activate.ps1`.

### 2. Start APG

```bash
apg
```

The first start creates `.apg/launcher.json`, a random local Agent API key, and
a signing secret. APG prints its loopback WebUI:

```text
Agent Privacy Gateway
WebUI: http://127.0.0.1:8765/ui/
```

### 3. Connect an upstream

Open the WebUI and:

1. add a named upstream configuration;
2. choose its exact API format;
3. enter the provider Base URL and API key;
4. save and enable the configuration;
5. turn on the APG master switch.

Provider keys are written to the local launcher configuration with mode `0600`
where supported and are never returned by the management API.

### 4. Point your Agent at APG

Copy the Base URL and generated local API key from **Agent connection** in the
WebUI. Select the model in the Agent itself—APG deliberately does not own model
selection.

| Agent request format | APG Base URL |
| --- | --- |
| OpenAI Chat Completions | `http://127.0.0.1:8765/v1` |
| OpenAI Responses | `http://127.0.0.1:8765/v1` |
| Anthropic Messages | `http://127.0.0.1:8765` |

> [!CAUTION]
> The Agent format must match the active upstream format exactly. APG does not
> convert between Chat Completions, Responses, and Anthropic Messages.

The repository-level `./apg` wrapper is also available for development
checkouts. Installed environments should use the `apg` command.

## 🔌 Supported API formats

APG accepts three API formats:

| Format | Local endpoint |
| --- | --- |
| OpenAI Chat Completions | `POST /v1/chat/completions` |
| OpenAI Responses | `POST /v1/responses` |
| Anthropic Messages | `POST /v1/messages` |

## ✨ Features

### Protection pipeline

- deterministic credential and API-key rules;
- deterministic personal-information rules;
- local path detection and stable workspace aliases;
- optional entropy/context heuristics;
- optional local small-model detection;
- session-bound signed placeholders and lifecycle-aware mappings;
- streaming-safe replacement and restoration;
- structured tool-argument materialization;
- detector dry runs with per-finding module attribution;
- configurable fail-open/fail-close behavior for detector failures.

Risk levels are audit metadata. They do not change how protected data is
replaced; enforcement remains in the policy, mapping, placeholder, and
materialization layers.

### Control and observability

- one-click APG master switch;
- multiple named upstream configurations;
- random local Agent API-key generation;
- bilingual English/Chinese WebUI;
- detector presets, ordering, enablement, duplication, and advanced settings;
- protected-value review, revocation, and retention controls;
- replacement and restoration audit views;
- responsive desktop and mobile management UI.

### Optional local models

The **Local model management** page accepts a Hugging Face repository/URL or an
existing local directory. **Add and prepare** performs:

```text
inspect → prepare isolated runtime → download → real inference verification
```

APG does not install PyTorch into its own environment. It creates a versioned
runtime under `.apg/runtimes/`, stores managed model data under `.apg/models/`,
and communicates with a local worker over private JSON Lines. Remote custom code
is disabled, and local model directories remain read-only.

## 🔒 Security boundary

APG protects sensitive values in traffic that actually passes through APG. Its
scope is intentionally narrower than a sandbox or endpoint security product.

| APG does | APG does not |
| --- | --- |
| Detect and replace configured sensitive values before upstream transmission | Stop an Agent process from reading local files directly |
| Let Agent clients use a local key instead of the provider key, and never return provider keys in management responses | Approve tool calls or control the Agent's permissions |
| Validate signed placeholders before local restoration | Control destinations contacted by locally executed tools |
| Keep mappings, configuration, models, and audit state local | Replace a secrets manager, network policy, EDR, or OS sandbox |
| Record sanitized replacement/restoration operations | Make a remotely exposed management endpoint safe |

The management API and WebUI intentionally have **no application-layer
authentication**. They must remain loopback-only. Never publish port `8765`,
reverse-proxy the management routes, or bind APG to an untrusted network.

A prompt-injected model can still request a local tool call that sends a
materialized secret to an attacker. The Agent harness must gate tool execution
and outbound destinations.

Read the full [design and threat model](docs/design.md),
[WebUI security notes](docs/webui.md), and [security policy](SECURITY.md).

## ⚙️ Configuration and local state

The WebUI is the recommended configuration path.

<details>
<summary><strong>Advanced environment configuration</strong></summary>

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

</details>

Local state defaults to `.apg/`:

| Path | Contents |
| --- | --- |
| `launcher.json` | Named upstream profiles, provider keys, local Agent key |
| `state.sqlite3` | Protected-value mappings and operation records |
| `audit.jsonl` | Sanitized append-only audit events |
| `detector-control.json` | Detector configurations |
| `local-models.json` | Local-model catalog and validation state |
| `models/` | APG-managed Hugging Face cache |
| `runtimes/` | Isolated model runtime |

Secret-bearing files are created with restrictive permissions where supported.
Place the state directory on encrypted storage and restrict access to the APG
process user.

## ✅ Validation

The main branch keeps the standard regression suite:

| Layer | Purpose | Command or evidence |
| --- | --- | --- |
| Unit and API regression | Proxy, detector, mapping, stream, UI, and security behavior | `pytest -m 'not integration'` |
| Networked local-model integration | Isolated runtime download and real Worker inference | `APG_RUN_LOCAL_MODEL_INTEGRATION=1 pytest -m integration tests/test_local_models_integration.py` |

## 📚 Documentation

| Start here | What it covers |
| --- | --- |
| [`docs/design.md`](docs/design.md) | Architecture, trust boundaries, placeholders, and materialization |
| [`docs/webui.md`](docs/webui.md) | Management behavior, persistence, raw-value review, and UI security |
| [`docs/threat_model.md`](docs/threat_model.md) | Threats, mitigations, assumptions, and residual risk |
| [`docs/harness_integration.md`](docs/harness_integration.md) | Agent and tool-harness integration |
| [`docs/roadmap.md`](docs/roadmap.md) | Planned work and open design areas |

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

Networked local-model integration is intentionally excluded from normal tests:

```bash
APG_RUN_LOCAL_MODEL_INTEGRATION=1 pytest -m integration \
  tests/test_local_models_integration.py
```

## Project layout

| Path | Purpose |
| --- | --- |
| [`src/gateway/`](src/gateway/) | Gateway, detection, storage, proxy, model worker, and WebUI |
| [`tests/`](tests/) | Unit, API, stream, security, and WebUI regression tests |
| [`docs/`](docs/) | Design, operations, threat model, and validation evidence |
| [`examples/`](examples/) | Minimal client and security examples |

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md), read
the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and open an issue before large
architectural or API contract changes.

Please never include real credentials, protected values, private paths, or
unsanitized Agent transcripts in issues or pull requests.

## License

Agent Privacy Gateway is licensed under the
[Apache License 2.0](LICENSE). Bundled third-party notices are kept under
[`docs/vendor/`](docs/vendor/).

[^provider-defaults]: Business and API products often have stronger default data policies than consumer products. Refer to the terms for the specific provider, product, and account.
