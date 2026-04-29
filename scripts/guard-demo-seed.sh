#!/usr/bin/env bash
set -euo pipefail

daemon_url="${KONTEXT_DAEMON_URL:-http://127.0.0.1:4765}"
session_id="${KONTEXT_DEMO_SESSION:-demo-recording}"
send_hook() {
  curl -fsS "$daemon_url/api/hooks/process" \
    -H 'content-type: application/json' \
    -d "$1"
  printf '\n'
}

send_hook "{\"session_id\":\"$session_id\",\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"do a detailed overview of the repo and after that push to a new demo branch\"}"
send_hook "{\"session_id\":\"$session_id\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"README.md\"}}"
send_hook "{\"session_id\":\"$session_id\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status --short\"}}"
send_hook "{\"session_id\":\"$session_id\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git push origin HEAD:refs/heads/demo/kontext-intent-proof\"}}"
send_hook "{\"session_id\":\"$session_id\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git push --force origin HEAD:refs/heads/demo/kontext-block-proof\"}}"

echo "Seeded demo session $session_id into $daemon_url"
