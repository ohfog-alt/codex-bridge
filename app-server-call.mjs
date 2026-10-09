#!/usr/bin/env node

import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";

const CODEX_BIN = process.env.CODEX_BIN ?? "codex";
const CODEX_ARGS = (process.env.CODEX_APP_SERVER_ARGS ?? "app-server proxy")
  .split(/\s+/u)
  .filter(Boolean);
const TRANSPORT = process.env.CODEX_TRANSPORT ?? "ndjson";
const TIMEOUT_MS = Number(process.env.CODEX_TIMEOUT_MS ?? "3000");
const INCLUDE_TOKEN = process.argv.includes("--include-token");
const PRINT_TOKEN = process.argv.includes("--print-token");

function frame(message) {
  if (TRANSPORT === "ndjson") {
    return Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
  }

  const body = Buffer.from(JSON.stringify(message), "utf8");
  return Buffer.concat([
    Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "ascii"),
    body,
  ]);
}

function redact(value) {
  if (!value || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redact(item));
  }

  const out = {};
  for (const [key, fieldValue] of Object.entries(value)) {
    if (key.toLowerCase().includes("token") && typeof fieldValue === "string" && !PRINT_TOKEN) {
      out[key] = {
        redacted: true,
        length: fieldValue.length,
        sha256Prefix: crypto.createHash("sha256").update(fieldValue).digest("hex").slice(0, 12),
      };
    } else {
      out[key] = redact(fieldValue);
    }
  }
  return out;
}

function parseFrames(buffer) {
  const messages = [];

  if (TRANSPORT === "ndjson") {
    let offset = 0;
    while (offset < buffer.length) {
      const lineEnd = buffer.indexOf("\n", offset, "utf8");
      if (lineEnd === -1) {
        break;
      }
      const line = buffer.subarray(offset, lineEnd).toString("utf8").trim();
      if (line) {
        messages.push(JSON.parse(line));
      }
      offset = lineEnd + 1;
    }
    return { messages, remaining: buffer.subarray(offset) };
  }

  let offset = 0;

  while (offset < buffer.length) {
    const headerEnd = buffer.indexOf("\r\n\r\n", offset, "ascii");
    if (headerEnd === -1) {
      break;
    }

    const header = buffer.subarray(offset, headerEnd).toString("ascii");
    const match = /^Content-Length:\s*(\d+)$/im.exec(header);
    if (!match) {
      throw new Error(`missing Content-Length in header: ${JSON.stringify(header)}`);
    }

    const contentLength = Number(match[1]);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + contentLength;
    if (buffer.length < bodyEnd) {
      break;
    }

    const body = buffer.subarray(bodyStart, bodyEnd).toString("utf8");
    messages.push(JSON.parse(body));
    offset = bodyEnd;
  }

  return { messages, remaining: buffer.subarray(offset) };
}

const child = spawn(CODEX_BIN, CODEX_ARGS, {
  stdio: ["pipe", "pipe", "pipe"],
});

let stdout = Buffer.alloc(0);
let stderr = "";
const messages = [];
let resolved = false;
let timedOut = false;

child.stdout.on("data", (chunk) => {
  stdout = Buffer.concat([stdout, chunk]);
  const parsed = parseFrames(stdout);
  stdout = parsed.remaining;
  messages.push(...parsed.messages);
  if (!resolved && messages.some((message) => message && message.id === 2)) {
    resolved = true;
    child.stdin.end();
  }
});

child.stderr.on("data", (chunk) => {
  stderr += chunk.toString("utf8");
});

child.on("error", (error) => {
  console.error(JSON.stringify({ error: error.message }, null, 2));
  process.exitCode = 1;
});

const initialize = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    clientInfo: {
      name: "codex-bridge-helper",
      title: "Codex Bridge Helper",
      version: "0.1.0",
    },
    capabilities: {
      experimentalApi: true,
      requestAttestation: false,
      optOutNotificationMethods: [],
    },
  },
};

const initialized = {
  jsonrpc: "2.0",
  method: "initialized",
};

const getAuthStatus = {
  jsonrpc: "2.0",
  id: 2,
  method: "getAuthStatus",
  params: {
    includeToken: INCLUDE_TOKEN,
    refreshToken: false,
  },
};

child.stdin.write(frame(initialize));
child.stdin.write(frame(initialized));
child.stdin.write(frame(getAuthStatus));

const exitCode = await new Promise((resolve) => {
  const timer = setTimeout(() => {
    if (!resolved) {
      timedOut = true;
      resolved = true;
      child.kill("SIGTERM");
    }
  }, TIMEOUT_MS);

  child.on("close", resolve);
  child.on("close", () => clearTimeout(timer));
});

if (stdout.length) {
  stderr += `unparsed stdout bytes: ${stdout.length}\n`;
}

console.log(JSON.stringify({
  command: `${CODEX_BIN} ${CODEX_ARGS.join(" ")}`,
  transport: TRANSPORT,
  includeTokenRequested: INCLUDE_TOKEN,
  printToken: PRINT_TOKEN,
  timeoutMs: TIMEOUT_MS,
  timedOut,
  exitCode,
  messages: messages.map((message) => redact(message)),
  stderr: stderr.trim() || null,
}, null, 2));

if (exitCode !== 0) {
  process.exitCode = exitCode ?? 1;
}
