import { Command } from "commander";
import { startCommand } from "./commands/start.js";
import { preToolUseCommand, postToolUseCommand } from "./commands/hook.js";
import { loginCommand } from "./commands/login.js";

const program = new Command();

program
  .name("kontext")
  .description("Kontext CLI — governed agent sessions for Claude Code")
  .version("0.1.0");

program
  .command("start")
  .description("Launch Claude Code with Kontext governance hooks")
  .option("--user <email>", "Developer identity (email)")
  .option("--api-url <url>", "Kontext API base URL")
  .argument("[args...]", "Additional arguments to pass to Claude Code")
  .action(async (args: string[], opts: { user?: string; apiUrl?: string }) => {
    await startCommand({ user: opts.user, apiUrl: opts.apiUrl, args });
  });

program
  .command("login")
  .description("Authenticate with Kontext via browser")
  .option("--api-url <url>", "Kontext API base URL")
  .action(async (opts: { apiUrl?: string }) => {
    await loginCommand({ apiUrl: opts.apiUrl });
  });

const hook = program
  .command("hook")
  .description("Claude Code hook handlers (internal)");

hook
  .command("pre-tool-use")
  .description("PreToolUse hook handler")
  .action(async () => {
    await preToolUseCommand();
  });

hook
  .command("post-tool-use")
  .description("PostToolUse hook handler")
  .action(async () => {
    await postToolUseCommand();
  });

program.parse();
