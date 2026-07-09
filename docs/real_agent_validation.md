# Real-Agent Validation

The project has normal unit/integration tests, but the thesis also needs real-agent tests: a coding agent should try the same scenarios a cloud agent would encounter, and APG should still enforce the intended boundary.

## Scenario Matrix

Run the deterministic local matrix first:

```bash
.venv/bin/python experiments/agent_scenario_matrix.py
```

It covers:

- recursive request redaction
- signed placeholder and materialization failures
- OpenAI-compatible proxy forwarding and response scanning
- DeepSeek upstream path mapping
- transparent tool-call argument materialization
- DeepSeek harness dry-run redaction

## OpenCode Runner

OpenCode is a real open-source coding agent. Run it against the same matrix without using your default OpenCode config:

```bash
.venv/bin/python experiments/agent_scenario_matrix.py --agent opencode --timeout 600
```

This creates temporary `XDG_CONFIG_HOME` and `XDG_DATA_HOME` directories, asks OpenCode not to edit files, and has it run/inspect the scenario commands.

If the model/backend hangs, stop it and keep the deterministic local matrix as the authoritative safety gate until credentials/provider config are stable.

## Sanitized Black-Box Probe

For safer third-party agent testing, use the black-box probe instead of exposing the repository. The probe uses only fake stress data and reports pass/fail evidence without printing raw fake secrets:

```bash
.venv/bin/python experiments/apg_blackbox_probe.py
```

To let a real external agent validate behavior, copy only this probe into a temporary directory and ask the agent to run it there. This avoids sending project source or private workspace context to the model while still exercising APG's public behavior.

An even safer mode is to start the local probe server yourself:

```bash
.venv/bin/python experiments/apg_blackbox_probe_server.py
```

Then ask the external agent, from an otherwise empty directory, to run:

```bash
curl http://127.0.0.1:8766/probe
```

In this mode the external agent sees only localhost JSON results, not source files, virtualenv contents, or repository paths.

Example with OpenCode and DeepSeek:

```bash
# Terminal 1
.venv/bin/python experiments/apg_blackbox_probe_server.py

# Terminal 2, from an empty directory
DEEPSEEK_API_KEY='<your key>' \
XDG_DATA_HOME=/private/tmp/opencode-deepseek-apg-probe-data \
XDG_CONFIG_HOME=/private/tmp/opencode-deepseek-apg-probe-config \
opencode run --model deepseek/deepseek-v4-flash \
  'Run this exact command: curl -s http://127.0.0.1:8766/probe . Then report whether ok=true and list scenario evidence codes. Do not inspect files or edit anything.'
```

Observed validation on 2026-07-02:

- OpenCode version: `1.17.9`
- DeepSeek model: `deepseek/deepseek-v4-flash`
- APG live harness status: `200`
- APG live harness request redactions: `3`
- OpenCode real-agent probe: top-level `ok=true`
- Black-box scenarios passed: `proxy_redaction_blackbox`, `placeholder_blackbox`, `deepseek_path_mapping_blackbox`

## DeepSeek Live Gate

Use the live DeepSeek API only through environment variables:

```bash
export DEEPSEEK_API_KEY='<your key>'
.venv/bin/python experiments/deepseek_agent_experiment.py --live --model deepseek-v4-flash
```

Do not pass the key as a command-line argument, commit it to config, or paste it into reusable scripts.
