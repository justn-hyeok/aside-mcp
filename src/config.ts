import { homedir } from "node:os";
import { join } from "node:path";

const configDir = process.env.ASIDE_MCP_CONFIG_DIR ?? join(homedir(), ".config", "aside-mcp");

const list = (value?: string) => (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);

export const config = {
  publicUrl: new URL(process.env.ASIDE_MCP_PUBLIC_URL ?? "http://127.0.0.1:7680"),
  port: Number(process.env.ASIDE_MCP_PORT ?? 7680),
  asideBin: process.env.ASIDE_BIN ?? join(homedir(), ".local", "bin", "aside"),
  passwordFile: join(configDir, "password"),
  stateFile: join(configDir, "state.json"),
  auditFile: process.env.ASIDE_MCP_AUDIT_FILE ?? join(homedir(), "Library", "Logs", "aside-mcp", "audit.jsonl"),
  extraDeniedHosts: list(process.env.ASIDE_MCP_DENY_HOSTS),
  extraRedirects: list(process.env.ASIDE_MCP_EXTRA_REDIRECTS),
};
