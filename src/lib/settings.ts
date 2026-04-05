import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * Generate a Claude Code hooks-only settings file.
 * This file is loaded alongside the user's existing settings via --settings.
 */
export function generateSettings(
  kontextBinaryPath: string,
  sessionDir: string,
): string {
  // Resolve the absolute path to node so hooks can find it
  const nodePath = process.execPath;

  const settings = {
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash|Edit|Write|mcp__.*",
          hooks: [
            {
              type: "command",
              command: `${nodePath} ${kontextBinaryPath} hook pre-tool-use`,
              timeout: 10,
            },
          ],
        },
      ],
      PostToolUse: [
        {
          matcher: ".*",
          hooks: [
            {
              type: "command",
              command: `${nodePath} ${kontextBinaryPath} hook post-tool-use`,
              timeout: 5,
              async: true,
            },
          ],
        },
      ],
    },
  };

  const settingsPath = join(sessionDir, "settings.json");
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  return settingsPath;
}

/**
 * Create a temporary session directory and return its path.
 */
export function createSessionDir(): string {
  const dir = join(tmpdir(), "kontext", `session-${process.pid}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Write session state to a JSON file in the session directory.
 */
export function writeSessionState(
  sessionDir: string,
  state: {
    sessionId: string;
    organizationId: string;
    agentId: string;
    userId: string;
    apiBaseUrl: string;
    accessToken: string;
  },
): string {
  const filePath = join(sessionDir, "session.json");
  writeFileSync(
    filePath,
    JSON.stringify(
      {
        ...state,
        createdAt: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  return filePath;
}
