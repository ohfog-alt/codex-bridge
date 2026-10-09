#!/usr/bin/env node

import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { readEnrollment } from "./lib/enrollment-store.mjs";

const CODEX_BIN = process.env.CODEX_BIN ?? "codex";
const BASE_URL = process.env.CHATGPT_BASE_URL ?? "https://chatgpt.com/backend-api";
const ENROLLMENT_PATH = process.env.CODEX_BRIDGE_ENROLLMENT_PATH;
const MANUAL_CODE = process.env.CODEX_REMOTE_MANUAL_PAIRING_CODE;
const ROUTES = (process.env.CODEX_REMOTE_PAIR_ROUTES ?? "/wham/remote/control/client/pair,/codex/remote/control/client/pair,/wham/remote/control/pair,/codex/remote/control/pair").split(",");

function frame(message) { return Buffer.from(`${JSON.stringify(message)}\n`, "utf8"); }
function parseNdjson(buffer) {
  const messages = [];
  let start = 0;
  for (;;) {
    const end = buffer.indexOf(0x0a, start);
    if (end < 0) break;
    const line = buffer.subarray(start, end).toString("utf8").trim();
    if (line) messages.push(JSON.parse(line));
    start = end + 1;
  }
  return { messages, remaining: buffer.subarray(start) };
}
function accountId(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return payload?.["https://api.openai.com/auth"]?.chatgpt_account_id ?? null;
  } catch { return null; }
}
async function authToken() {
  const child = spawn(CODEX_BIN, ["app-server", "--stdio"], { stdio: ["pipe", "pipe", "ignore"] });
  let buffer = Buffer.alloc(0);
  const response = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("auth timeout")), 8000);
    child.stdout.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const parsed = parseNdjson(buffer); buffer = parsed.remaining;
      const result = parsed.messages.find((message) => message?.id === 2);
      if (result) { clearTimeout(timer); resolve(result); child.stdin.end(); }
    });
    child.stdin.write(frame({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "codex-bridge-helper", version: "0.1.0" }, capabilities: { experimentalApi: true } } }));
    child.stdin.write(frame({ jsonrpc: "2.0", method: "initialized" }));
    child.stdin.write(frame({ jsonrpc: "2.0", id: 2, method: "getAuthStatus", params: { includeToken: true, refreshToken: true } }));
  });
  if (!response.result?.authToken) throw new Error("getAuthStatus returned no token");
  return response.result.authToken;
}
async function manualCode() {
  if (MANUAL_CODE) return MANUAL_CODE;
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  const parsed = JSON.parse(text);
  const code = parsed?.manual_pairing_code ?? parsed?.manualPairingCode;
  if (!code) throw new Error("stdin pairing response had no manual_pairing_code");
  return code;
}
async function main() {
  if (!ENROLLMENT_PATH) throw new Error("Set CODEX_BRIDGE_ENROLLMENT_PATH");
  const code = await manualCode();
  const enrollment = readEnrollment(ENROLLMENT_PATH);
  const token = await authToken();
  for (const route of ROUTES) {
    const response = await fetch(`${BASE_URL}${route}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "chatgpt-account-id": accountId(token), "content-type": "application/json", "user-agent": "codex-bridge-helper/0.1" },
      body: JSON.stringify({ client_id: enrollment.clientId, manual_pairing_code: code }),
    });
    const body = await response.text();
    let detail = null;
    try { detail = JSON.parse(body)?.detail ?? JSON.parse(body)?.error ?? null; } catch {}
    console.log(JSON.stringify({ route, status: response.status, ok: response.ok, detail: typeof detail === "string" ? detail : null }));
    if (response.ok) return;
  }
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
