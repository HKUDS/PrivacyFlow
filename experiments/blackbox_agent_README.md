# APG Black-Box Validation

This directory is a sanitized validation fixture for a real coding agent.

Rules for the agent:

- Do not inspect files outside this directory.
- Do not edit files.
- Run `.venv/bin/python apg_blackbox_probe.py`.
- Report whether the JSON result has `"ok": true`.
- Report the scenario names and evidence codes only.

The probe uses fake stress data and should not print raw fake secrets.
