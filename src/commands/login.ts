import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { URL } from "node:url";
import { storeLoginCredentials } from "../lib/auth.js";

export interface LoginOptions {
  apiUrl?: string;
}

/**
 * Browser-based PKCE login flow.
 * Opens the browser to Kontext's OAuth authorization endpoint,
 * waits for the callback, exchanges the code for tokens.
 */
export async function loginCommand(options: LoginOptions): Promise<void> {
  const apiBaseUrl =
    options.apiUrl ??
    process.env["KONTEXT_API_URL"] ??
    "https://api.kontext.dev";

  // Generate PKCE verifier and challenge
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const state = randomBytes(16).toString("base64url");

  // Start local callback server
  const { port, waitForCallback, close } = await startCallbackServer(state);
  const redirectUri = `http://localhost:${port}/callback`;

  const authUrl = new URL(`${apiBaseUrl}/oauth2/auth`);
  authUrl.searchParams.set("client_id", "kontext-cli");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("scope", "openid email profile");

  console.error("Opening browser for login...");
  console.error(`If the browser doesn't open, visit: ${authUrl.toString()}\n`);

  // Dynamic import so `open` isn't loaded in hook paths
  const { default: openBrowser } = await import("open");
  await openBrowser(authUrl.toString());

  // Wait for the OAuth callback
  const code = await waitForCallback();
  close();

  // Exchange code for tokens
  console.error("Exchanging code for tokens...");
  const tokenRes = await fetch(`${apiBaseUrl}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "kontext-cli",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`Token exchange failed (${tokenRes.status}): ${text}`);
  }

  const tokenData = (await tokenRes.json()) as {
    access_token: string;
    id_token?: string;
    expires_in?: number;
  };

  // Decode email from id_token if available, otherwise from userinfo
  let email = "unknown";
  if (tokenData.id_token) {
    try {
      const payload = JSON.parse(
        Buffer.from(tokenData.id_token.split(".")[1]!, "base64url").toString(),
      ) as { email?: string };
      if (payload.email) email = payload.email;
    } catch {
      // Fall through to userinfo
    }
  }

  if (email === "unknown") {
    try {
      const userinfoRes = await fetch(`${apiBaseUrl}/oauth2/userinfo`, {
        headers: { authorization: `Bearer ${tokenData.access_token}` },
      });
      if (userinfoRes.ok) {
        const userinfo = (await userinfoRes.json()) as { email?: string };
        if (userinfo.email) email = userinfo.email;
      }
    } catch {
      // Best-effort
    }
  }

  storeLoginCredentials({
    email,
    accessToken: tokenData.access_token,
    expiresAt: tokenData.expires_in
      ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
      : undefined,
  });

  console.error(`Logged in as ${email}`);
}

function startCallbackServer(expectedState: string): Promise<{
  port: number;
  waitForCallback: () => Promise<string>;
  close: () => void;
}> {
  return new Promise((resolveServer) => {
    let resolveCode: (code: string) => void;
    let rejectCode: (err: Error) => void;

    const codePromise = new Promise<string>((res, rej) => {
      resolveCode = res;
      rejectCode = rej;
    });

    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", `http://localhost`);
      if (url.pathname !== "/callback") {
        res.writeHead(404);
        res.end("Not found");
        return;
      }

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<h1>Login failed</h1><p>You can close this tab.</p>");
        rejectCode(new Error(`OAuth error: ${error}`));
        return;
      }

      if (state !== expectedState) {
        res.writeHead(400, { "content-type": "text/html" });
        res.end("<h1>State mismatch</h1><p>Please try again.</p>");
        rejectCode(new Error("OAuth state mismatch"));
        return;
      }

      if (!code) {
        res.writeHead(400, { "content-type": "text/html" });
        res.end("<h1>Missing code</h1><p>Please try again.</p>");
        rejectCode(new Error("No authorization code received"));
        return;
      }

      res.writeHead(200, { "content-type": "text/html" });
      res.end(
        "<h1>Login successful!</h1><p>You can close this tab and return to the terminal.</p>",
      );
      resolveCode(code);
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolveServer({
        port,
        waitForCallback: () => codePromise,
        close: () => server.close(),
      });
    });
  });
}
