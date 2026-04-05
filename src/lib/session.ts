import { randomUUID } from "node:crypto";
import { hostname } from "node:os";

export interface SessionState {
  sessionId: string;
  organizationId: string;
  agentId: string;
  userId: string;
  apiBaseUrl: string;
  accessToken: string;
  createdAt: string;
}

interface CreateSessionResponse {
  sessionId: string;
  name: string;
}

/**
 * Create an agent session via the Kontext API.
 */
export async function createSession(
  apiBaseUrl: string,
  accessToken: string,
  authenticatedUserId: string,
): Promise<CreateSessionResponse> {
  const res = await fetch(`${apiBaseUrl}/api/v1/agent-sessions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      tokenIdentifier: `cli:${randomUUID()}`,
      authenticatedUserId,
      clientSessionId: randomUUID(),
      hostname: hostname(),
      clientInfo: { name: "kontext-cli", version: "0.1.0" },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to create session (${res.status}): ${text}`);
  }

  return (await res.json()) as CreateSessionResponse;
}

/**
 * Send a heartbeat for an active session.
 */
export async function heartbeatSession(
  apiBaseUrl: string,
  accessToken: string,
  sessionId: string,
): Promise<void> {
  const res = await fetch(
    `${apiBaseUrl}/api/v1/agent-sessions/${sessionId}/heartbeat`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!res.ok) {
    // Non-fatal — log but don't throw
    console.error(`Heartbeat failed (${res.status})`);
  }
}

/**
 * Disconnect an agent session.
 */
export async function disconnectSession(
  apiBaseUrl: string,
  accessToken: string,
  sessionId: string,
): Promise<void> {
  try {
    await fetch(`${apiBaseUrl}/api/v1/agent-sessions/${sessionId}/disconnect`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`,
      },
    });
  } catch {
    // Best-effort on shutdown
  }
}

/**
 * Report a tool evaluation event to the Kontext API.
 */
export async function evaluateTool(
  apiBaseUrl: string,
  accessToken: string,
  sessionId: string,
  body: {
    toolName: string;
    toolInput: Record<string, unknown>;
    hookEvent: "PreToolUse" | "PostToolUse";
    claudeSessionId?: string;
    cwd?: string;
  },
): Promise<{ decision: "allow" | "deny"; reason: string; eventId?: string }> {
  const res = await fetch(
    `${apiBaseUrl}/api/v1/agent-sessions/${sessionId}/evaluate-tool`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
    },
  );

  if (!res.ok) {
    // Fail-open: if the API is unreachable, allow the tool call
    return { decision: "allow", reason: "API_UNREACHABLE" };
  }

  return (await res.json()) as {
    decision: "allow" | "deny";
    reason: string;
    eventId?: string;
  };
}
