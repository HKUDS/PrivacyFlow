#!/usr/bin/env sh
set -eu

curl http://localhost:8765/v1/chat/completions \
  -H 'Authorization: Bearer pf-local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4.1-mini",
    "messages": [
      {
        "role": "user",
        "content": "Please help debug /Users/alice/private/project and do not leak sk-example-abcdefghijklmnopqrstuvwxyz123456."
      }
    ]
  }'
