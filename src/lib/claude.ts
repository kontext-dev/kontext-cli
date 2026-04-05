import { spawn, type ChildProcess } from "node:child_process";

export interface ClaudeLaunchOptions {
  settingsPath: string;
  sessionFilePath: string;
  extraArgs?: string[];
}

/**
 * Spawn Claude Code as a child process with governance settings.
 * Uses stdio: 'inherit' so the developer interacts directly with Claude.
 */
export function launchClaude(options: ClaudeLaunchOptions): ChildProcess {
  const args = ["--settings", options.settingsPath];

  if (options.extraArgs) {
    args.push(...options.extraArgs);
  }

  const child = spawn("claude", args, {
    stdio: "inherit",
    env: {
      ...process.env,
      KONTEXT_SESSION_FILE: options.sessionFilePath,
    },
  });

  return child;
}

/**
 * Set up signal forwarding from parent to child process,
 * and return a promise that resolves when the child exits.
 */
export function setupLifecycle(
  child: ChildProcess,
  onExit: () => Promise<void>,
): Promise<number> {
  return new Promise<number>((resolve) => {
    const forward = (signal: NodeJS.Signals) => {
      child.kill(signal);
    };

    process.on("SIGINT", () => forward("SIGINT"));
    process.on("SIGTERM", () => forward("SIGTERM"));

    child.on("exit", async (code) => {
      await onExit();
      resolve(code ?? 0);
    });
  });
}
