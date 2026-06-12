import type { SourceFile } from "@repo/shared";

export function extractMoveFunctions(file: SourceFile) {
  const lines = file.content.split(/\r?\n/);
  const functions: Array<{
    body: string;
    isPublicEntry: boolean;
    name: string;
    signature: string;
    startLine: number;
    endLine: number;
  }> = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = line.match(
      /\b((?:(?:public(?:\([^)]+\))?|entry|native)\s+)*)fun\s+([A-Za-z_][A-Za-z0-9_]*)/,
    );
    if (!match) continue;

    const startLine = index + 1;
    let braceDepth = 0;
    let seenBrace = false;
    const bodyLines: string[] = [];
    for (let cursor = index; cursor < lines.length; cursor += 1) {
      const current = lines[cursor] ?? "";
      bodyLines.push(current);
      for (const char of current) {
        if (char === "{") {
          braceDepth += 1;
          seenBrace = true;
        } else if (char === "}") {
          braceDepth -= 1;
        }
      }
      if (seenBrace && braceDepth <= 0) {
        functions.push({
          body: bodyLines.join("\n"),
          endLine: cursor + 1,
          isPublicEntry: /\bpublic\b/.test(match[1] ?? "") && /\bentry\b/.test(match[1] ?? ""),
          name: match[2] ?? "unknown",
          signature: bodyLines.join("\n").split("{")[0] ?? line,
          startLine,
        });
        index = cursor;
        break;
      }
    }
  }

  return functions;
}

export function hasSourceAuthSignal(body: string) {
  return /assert!|tx_context::sender|ctx\.sender|sender\(|object::owner|owner|has_owner|address_of|borrow_global|exists</i.test(
    body,
  );
}

export function hasSenderRecipientBinding(body: string) {
  return /(recipient|receiver|to|dst|destination)\s*==\s*(sender|tx_context::sender|ctx\.sender)|assert!\s*\([^)]*(recipient|receiver|to|dst|destination)[^)]*(sender|tx_context::sender|ctx\.sender)|owner|beneficiary|entitlement|allowlist|whitelist/i.test(
    body,
  );
}

export function sourceEvidence(
  file: SourceFile,
  fn: { body: string; endLine: number; name: string; startLine: number },
) {
  return {
    codeSnippet: sourceSnippet(file, fn.startLine, fn.endLine),
    detail: `Source function ${fn.name} spans ${file.path}:${fn.startLine}-${fn.endLine}.`,
    filePath: file.path,
    functionName: fn.name,
    lineEnd: fn.endLine,
    lineStart: fn.startLine,
    moduleName: moduleNameFromPath(file.path),
  };
}

export function findSourceMarker(file: SourceFile, pattern: RegExp) {
  const lines = file.content.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  if (index === -1) return undefined;
  return {
    codeSnippet: sourceSnippet(file, index + 1, index + 1),
    detail: `${file.path}:${index + 1} contains "${lines[index]?.trim()}".`,
    filePath: file.path,
    lineStart: index + 1,
    moduleName: moduleNameFromPath(file.path),
  };
}

export function sourceSnippet(file: SourceFile, startLine: number, endLine: number) {
  const lines = file.content.split(/\r?\n/);
  const start = Math.max(1, startLine - 2);
  const end = Math.min(lines.length, endLine + 2);
  return lines
    .slice(start - 1, end)
    .map((line, index) => `${String(start + index).padStart(4, " ")} | ${line}`)
    .join("\n");
}

export function moduleNameFromPath(path: string) {
  return path.split(/[\\/]/).pop()?.replace(/\.move$/i, "") ?? "source";
}
