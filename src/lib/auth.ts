import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CREDENTIALS_PATH = join(homedir(), ".kontext", "credentials.json");

export interface KontextCredentials {
  accessToken: string;
  tokenType: string;
  expiresAt?: string;
}

export interface DeveloperIdentity {
  email: string;
  source: "login" | "git" | "flag";
}

/**
 * Authenticate as a service account using client_credentials grant.
 */
export async function authenticateServiceAccount(
  apiBaseUrl: string,
  clientId: string,
  clientSecret: string,
): Promise<KontextCredentials> {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  const res = await fetch(`${apiBaseUrl}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "management:all mcp:invoke",
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Service account auth failed (${res.status}): ${text}`);
  }

  const data = (await res.json()) as {
    access_token: string;
    token_type: string;
    expires_in?: number;
  };

  return {
    accessToken: data.access_token,
    tokenType: data.token_type,
    expiresAt: data.expires_in
      ? new Date(Date.now() + data.expires_in * 1000).toISOString()
      : undefined,
  };
}

/**
 * Resolve the developer's identity.
 * Priority: stored login > git config > --user flag.
 */
export function resolveDeveloperIdentity(userFlag?: string): DeveloperIdentity {
  // 1. Check for stored login credentials
  try {
    const raw = readFileSync(CREDENTIALS_PATH, "utf-8");
    const stored = JSON.parse(raw) as { email?: string };
    if (stored.email) {
      return { email: stored.email, source: "login" };
    }
  } catch {
    // No stored credentials, continue
  }

  // 2. Try git config
  try {
    const email = execSync("git config user.email", {
      encoding: "utf-8",
      timeout: 5000,
    }).trim();
    if (email) {
      return { email, source: "git" };
    }
  } catch {
    // Git not available or no email configured
  }

  // 3. Explicit flag
  if (userFlag) {
    return { email: userFlag, source: "flag" };
  }

  throw new Error(
    "Could not resolve developer identity. Run `kontext login` or pass --user <email>.",
  );
}

/**
 * Store login credentials from a browser PKCE flow.
 */
export function storeLoginCredentials(credentials: {
  email: string;
  accessToken: string;
  expiresAt?: string;
}): void {
  const dir = join(homedir(), ".kontext");
  mkdirSync(dir, { recursive: true });
  writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2));
}

/**
 * Read stored login credentials.
 */
export function readStoredCredentials(): {
  email: string;
  accessToken: string;
  expiresAt?: string;
} | null {
  try {
    const raw = readFileSync(CREDENTIALS_PATH, "utf-8");
    return JSON.parse(raw) as {
      email: string;
      accessToken: string;
      expiresAt?: string;
    };
  } catch {
    return null;
  }
}
