import { rmSync } from "node:fs";
import { resolve } from "node:path";
import {
  authenticateServiceAccount,
  resolveDeveloperIdentity,
} from "../lib/auth.js";
import {
  createSession,
  heartbeatSession,
  disconnectSession,
} from "../lib/session.js";
import {
  createSessionDir,
  generateSettings,
  writeSessionState,
} from "../lib/settings.js";
import { launchClaude, setupLifecycle } from "../lib/claude.js";

export interface StartOptions {
  user?: string;
  apiUrl?: string;
  args?: string[];
}

export async function startCommand(options: StartOptions): Promise<void> {
  const apiBaseUrl =
    options.apiUrl ??
    process.env["KONTEXT_API_URL"] ??
    "https://api.kontext.security";
  const clientId = process.env["KONTEXT_CLIENT_ID"];
  const clientSecret = process.env["KONTEXT_CLIENT_SECRET"];

  if (!clientId || !clientSecret) {
    console.error(
      "Missing KONTEXT_CLIENT_ID and KONTEXT_CLIENT_SECRET environment variables.",
    );
    process.exit(1);
  }

  // 1. Authenticate as service account
  console.error("Authenticating...");
  const credentials = await authenticateServiceAccount(
    apiBaseUrl,
    clientId,
    clientSecret,
  );

  // 2. Resolve developer identity
  const developer = resolveDeveloperIdentity(options.user);
  console.error(`Developer: ${developer.email} (via ${developer.source})`);

  // 3. Create agent session
  console.error("Creating session...");
  const session = await createSession(
    apiBaseUrl,
    credentials.accessToken,
    developer.email,
  );
  console.error(`Session: ${session.name} (${session.sessionId})`);

  // 4. Write session state and generate settings
  const sessionDir = createSessionDir();
  const sessionFilePath = writeSessionState(sessionDir, {
    sessionId: session.sessionId,
    // These are derived from the service account — the API resolves them
    organizationId: "",
    agentId: "",
    userId: developer.email,
    apiBaseUrl,
    accessToken: credentials.accessToken,
  });

  const kontextBinary = resolve(process.argv[1] ?? "kontext");
  const settingsPath = generateSettings(kontextBinary, sessionDir);

  // 5. Launch Claude Code
  console.error("Launching Claude Code with Kontext governance...\n");
  const child = launchClaude({
    settingsPath,
    sessionFilePath,
    extraArgs: options.args,
  });

  // 6. Start heartbeat
  const heartbeatInterval = setInterval(() => {
    void heartbeatSession(
      apiBaseUrl,
      credentials.accessToken,
      session.sessionId,
    );
  }, 60_000);

  // 7. Wait for exit and clean up
  const exitCode = await setupLifecycle(child, async () => {
    clearInterval(heartbeatInterval);
    console.error("\nDisconnecting session...");
    await disconnectSession(
      apiBaseUrl,
      credentials.accessToken,
      session.sessionId,
    );
    try {
      rmSync(sessionDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  process.exit(exitCode);
}
