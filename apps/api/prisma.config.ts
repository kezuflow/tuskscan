import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { defineConfig, env } from "prisma/config";

loadLocalEnvFiles();

export default defineConfig({
  datasource: {
    url: env("DATABASE_URL"),
  },
  schema: "prisma/schema.prisma",
});

function loadLocalEnvFiles() {
  const protectedKeys = new Set(Object.keys(process.env));
  for (const file of [".env", ".env.local"]) {
    const path = resolve(process.cwd(), file);
    if (!existsSync(path)) continue;
    for (const [key, value] of Object.entries(parseEnvFile(readFileSync(path, "utf8")))) {
      if (!protectedKeys.has(key)) {
        process.env[key] = value;
      }
    }
  }
}

function parseEnvFile(contents: string) {
  const values: Record<string, string> = {};
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    values[match[1]!] = normalizeEnvValue(match[2] ?? "");
  }
  return values;
}

function normalizeEnvValue(raw: string) {
  const value = raw.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1).replaceAll("\\n", "\n");
  }
  const commentStart = value.indexOf(" #");
  return commentStart === -1 ? value : value.slice(0, commentStart).trim();
}
