# Threat Model

## Protected

- Accidental prompt leakage of API keys, tokens, private keys, emails, phone numbers, credit cards, local paths, and config secrets
- Raw machine secrets being sent to cloud LLM providers through APG
- Model outputs that echo secret-like content
- Prompt injection asking for secrets, placeholders, or secret forwarding
- Fake placeholders in files, prompts, code blocks, JSON, or shell snippets
- Some retry-loop behavior through stable non-retryable errors
- Forged placeholders inside tool-call argument fields

## Not Fully Protected

- Semantic inference from sanitized context
- User-approved or manually pasted sensitive data
- Agents, tools, or shell commands that bypass APG
- Provider-hosted tools that execute remotely without local mediation
- Unknown secret formats missed by rule-based detectors
- All possible PII re-identification
- Local malware or compromised OS accounts
- Tool calls that exfiltrate secrets via unsafe harness execution — APG materializes secrets into tool_call arguments by design (so the harness can execute authenticated tools transparently); the harness is responsible for approving/routing tool execution, domain allowlists, and unsafe-call protection.
- Destructive file writes or redacted-view overwrites — those are harness/editor/VCS responsibilities, not APG responsibilities.

## Premise

The cloud agent must send local context through APG before it reaches a remote model. Tool execution, network routing, file writes, and human approvals must be mediated by the agent harness. If an agent independently reads files, runs shell commands, accesses browsers, calls secret stores, or executes unsafe materialized tool calls, APG cannot enforce those boundaries.
