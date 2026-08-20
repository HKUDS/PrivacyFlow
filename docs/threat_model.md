# Threat Model

## Protected

- Accidental prompt leakage of detected API keys, tokens, private keys, emails, phone numbers, credit cards, local paths, and config secrets in supported textual fields
- Detected machine secrets in supported textual fields being sent to cloud LLM providers through PrivacyFlow
- Model outputs that echo secret-like content
- Prompt injection asking for secrets, placeholders, or secret forwarding
- Fake placeholders in files, prompts, code blocks, JSON, or shell snippets
- Some retry-loop behavior through stable non-retryable errors
- Forged placeholders inside tool-call argument fields

## Not Fully Protected

- Semantic inference from sanitized context
- User-approved or manually pasted sensitive data
- Agents, tools, or shell commands that bypass PrivacyFlow
- Provider-hosted tools that execute remotely without local mediation
- Unknown secret formats missed by rule-based detectors
- Raw values in protocol identifiers or opaque multimodal fields such as `image_url`, `file_data`, audio, images, and screenshots; those fields bypass scanning
- All possible PII re-identification
- Local malware or compromised OS accounts
- Tool calls that exfiltrate secrets via unsafe harness execution — PrivacyFlow materializes secrets into tool_call arguments by design (so the harness can execute authenticated tools transparently); the harness is responsible for approving/routing tool execution, domain allowlists, and unsafe-call protection.
- Destructive file writes or redacted-view overwrites — those are harness/editor/VCS responsibilities, not PrivacyFlow responsibilities.
- Findings whose detector action is `block` — the current policy replaces detected secrets but does not reject the whole upstream request.

## Premise

The cloud agent must send supported textual context through PrivacyFlow before it reaches a remote model. Tool execution, network routing, file writes, and human approvals must be mediated by the agent harness. The `local_tool` label only means that PrivacyFlow recognized a tool-argument field in a model response; it is not proof that the tool is local or approved. If an agent bypasses PrivacyFlow, sends opaque multimodal data, or executes unsafe materialized tool calls, PrivacyFlow cannot enforce those boundaries.
