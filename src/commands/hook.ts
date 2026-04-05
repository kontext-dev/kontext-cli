import { readFileSync } from "node:fs";
import { evaluateTool } from "../lib/session.js";

interface SessionState {
  sessionId: string;
  apiBaseUrl: string;
  accessToken: string;
}

interface HookInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: unknown;
  cwd?: string;
  hook_event_name?: string;
}

function readSessionState(): SessionState {
  const sessionFile = process.env["KONTEXT_SESSION_FILE"];
  if (!sessionFile) {
    throw new Error("KONTEXT_SESSION_FILE not set");
  }
  const raw = readFileSync(sessionFile, "utf-8");
  return JSON.parse(raw) as SessionState;
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString()));
    process.stdin.on("error", reject);
  });
}

/**
 * PreToolUse hook handler.
 * MVP: logs the event and always allows (telemetry-only).
 */
export async function preToolUseCommand(): Promise<void> {
  try {
    const raw = await readStdin();
    const input = JSON.parse(raw) as HookInput;
    const state = readSessionState();

    const result = await evaluateTool(
      state.apiBaseUrl,
      state.accessToken,
      state.sessionId,
      {
        toolName: input.tool_name,
        toolInput: input.tool_input,
        hookEvent: "PreToolUse",
        claudeSessionId: input.session_id,
        cwd: input.cwd,
      },
    );

    // MVP: always allow. Phase 2 will check result.decision.
    if (result.decision === "deny") {
      // Phase 2: uncomment to enforce blocking
      // process.stderr.write(`Blocked by Kontext policy: ${result.reason}`);
      // process.exit(2);
    }

    // Output hook response JSON for Claude Code
    const response = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow" as const,
        additionalContext: result.eventId
          ? `[Kontext: event ${result.eventId}]`
          : undefined,
      },
    };
    process.stdout.write(JSON.stringify(response));
    process.exit(0);
  } catch {
    // Non-blocking error: exit 1 means proceed (fail-open)
    process.exit(1);
  }
}

/**
 * PostToolUse hook handler.
 * Logs the completed tool call for telemetry. Always exits 0.
 */
export async function postToolUseCommand(): Promise<void> {
  try {
    const raw = await readStdin();
    const input = JSON.parse(raw) as HookInput;
    const state = readSessionState();

    await evaluateTool(state.apiBaseUrl, state.accessToken, state.sessionId, {
      toolName: input.tool_name,
      toolInput: input.tool_input,
      hookEvent: "PostToolUse",
      claudeSessionId: input.session_id,
      cwd: input.cwd,
    });
  } catch {
    // Best-effort telemetry
  }

  process.exit(0);
}
