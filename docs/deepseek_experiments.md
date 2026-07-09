# DeepSeek Experiments

DeepSeek's official OpenAI-compatible API uses:

- `base_url`: `https://api.deepseek.com`
- current models: `deepseek-v4-flash` and `deepseek-v4-pro`

APG exposes local OpenAI-compatible routes under `/v1`, while DeepSeek's upstream chat route is `/chat/completions`. Use `strip_local_v1: true` for DeepSeek upstreams.

## Safe Harness

The experiment runner does not accept API keys as command-line arguments and does not write them into the repository. It reads `DEEPSEEK_API_KEY` from the environment only.

Dry run:

```bash
.venv/bin/python experiments/deepseek_agent_experiment.py
```

Live DeepSeek smoke test:

```bash
export DEEPSEEK_API_KEY='<your key>'
.venv/bin/python experiments/deepseek_agent_experiment.py --live --model deepseek-v4-flash
```

The script starts APG in-process, sends an OpenAI-compatible chat request through `/v1/chat/completions`, and reports only coarse metrics:

- HTTP status
- model name
- request redaction count
- response redaction count
- whether the returned body still contains the fake stress-test secret
- a short assistant excerpt

## OpenCode

OpenCode is an open-source AI coding assistant. DeepSeek's docs recommend OpenCode version `>= 1.14.24`; this machine currently has `opencode 1.17.9`.

For interactive OpenCode experiments, prefer a temporary config/data directory while testing credentials:

```bash
mkdir -p /private/tmp/opencode-apg-config /private/tmp/opencode-apg-data
XDG_CONFIG_HOME=/private/tmp/opencode-apg-config \
XDG_DATA_HOME=/private/tmp/opencode-apg-data \
opencode providers list
```

Then connect DeepSeek interactively with `/connect` as described in DeepSeek's OpenCode guide. Avoid committing OpenCode auth files or placing raw API keys in shell scripts.

OpenCode also works non-interactively with `DEEPSEEK_API_KEY` in the environment:

```bash
DEEPSEEK_API_KEY='<your key>' \
XDG_DATA_HOME=/private/tmp/opencode-deepseek-data \
XDG_CONFIG_HOME=/private/tmp/opencode-deepseek-config \
opencode run --model deepseek/deepseek-v4-flash 'Reply with exactly APG_OK'
```

Keep the key out of checked-in config and scripts.
