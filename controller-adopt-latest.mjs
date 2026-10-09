#!/usr/bin/env node

import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { loadOrCreateSoftwareDeviceKey } from "./lib/device-key.mjs";
import {
  DEFAULT_ENROLLMENT_PATH,
  buildEnrollmentRecord,
  writeEnrollment,
} from "./lib/enrollment-store.mjs";

const CODEX_BIN = process.env.CODEX_BIN ?? "codex";
const CODEX_ARGS = (process.env.CODEX_APP_SERVER_ARGS ?? "app-server --stdio")
  .split(/\s+/u)
  .filter(Boolean);
const BASE_URL = process.env.CHATGPT_BASE_URL ?? "https://chatgpt.com/backend-api";
const ACCOUNT_ID = process.env.CHATGPT_ACCOUNT_ID;
const TIMEOUT_MS = Number(process.env.CODEX_TIMEOUT_MS ?? "5000");
const DEVICE_KEY_PATH = process.env.CODEX_BRIDGE_DEVICE_KEY_PATH ??
  path.join(os.homedir(), ".codex-bridge", "controller-device-key.json");
const ENROLLMENT_PATH = process.env.CODEX_BRIDGE_ENROLLMENT_PATH ?? DEFAULT_ENROLLMENT_PATH;
const EXPECT_CLIENT_PREFIX = process.env.CODEX_EXPECT_CLIENT_PREFIX;
const EXPECT_CLIENT_SUFFIX = process.env.CODEX_EXPECT_CLIENT_SUFFIX;

function frame(message) {
  return Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
}

function parseNdjson(buffer) {
  const messages = [];
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

function chatgptAccountId(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    const auth = payload?.["https://api.openai.com/auth"];
    return auth?.chatgpt_account_id ?? auth?.account_id ?? null;
  } catch {
    return null;
  }
}

function redactString(value, keepEdge = false) {
  if (typeof value !== "string") {
    return value;
  }
  if (!keepEdge || value.length <= 12) {
    return { redacted: true, length: value.length };
  }
  return { redacted: true, length: value.length, prefix: value.slice(0, 8), suffix: value.slice(-4) };
}

function sanitize(value, key = "") {
  const lowered = key.toLowerCase();
  if (typeof value === "string") {
    if (
      lowered.includes("token") ||
      lowered.includes("secret") ||
      lowered.includes("authorization") ||
      lowered.includes("cursor") ||
      lowered.includes("account_user_id") ||
      lowered.includes("accountuserid") ||
      lowered === "user_id" ||
      lowered === "publickeyspkiderbase64"
    ) {
      return redactString(value, false);
    }
    if (
      lowered.endsWith("_id") ||
      lowered.endsWith("id") ||
      lowered === "client_id" ||
      lowered === "clientid" ||
      lowered === "key_id" ||
      lowered === "keyid"
    ) {
      return redactString(value, true);
    }
    return value;
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitize(item, key));
  }
  const out = {};
  for (const [field, fieldValue] of Object.entries(value)) {
    out[field] = sanitize(fieldValue, field);
  }
  return out;
}

async function getAuthStatusWithToken() {
  const child = spawn(CODEX_BIN, CODEX_ARGS, { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = Buffer.alloc(0);
  let stderr = "";
  const messages = [];
  let response;
  const closePromise = new Promise((resolve) => child.on("close", resolve));

  child.stdout.on("data", (chunk) => {
    stdout = Buffer.concat([stdout, chunk]);
    const parsed = parseNdjson(stdout);
    stdout = parsed.remaining;
    messages.push(...parsed.messages);
    response = messages.find((message) => message && message.id === 2);
    if (response) {
      child.stdin.end();
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  child.stdin.write(frame({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      clientInfo: { name: "codex-bridge-helper", title: "Codex Bridge Helper", version: "0.1.0" },
      capabilities: { experimentalApi: true, requestAttestation: false, optOutNotificationMethods: [] },
    },
  }));
  child.stdin.write(frame({ jsonrpc: "2.0", method: "initialized" }));
  child.stdin.write(frame({
    jsonrpc: "2.0",
    id: 2,
    method: "getAuthStatus",
    params: { includeToken: true, refreshToken: true },
  }));

  const timedOut = await Promise.race([
    new Promise((resolve) => setTimeout(() => resolve(true), TIMEOUT_MS)),
    closePromise.then(() => false),
  ]);
  if (timedOut) {
    child.kill("SIGTERM");
    await closePromise;
  }
  if (!response) {
    throw new Error(`getAuthStatus did not return response id 2; stderr=${JSON.stringify(stderr.trim())}`);
  }
  if (response.error) {
    throw new Error(`getAuthStatus error: ${JSON.stringify(response.error)}`);
  }
  const token = response.result?.authToken;
  if (!token) {
    throw new Error("getAuthStatus returned no authToken");
  }
  return token;
}

async function fetchJson(pathname, token) {
  const accountId = ACCOUNT_ID ?? chatgptAccountId(token);
  const headers = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
    "user-agent": "codex-bridge-helper/0.1",
  };
  if (accountId) {
    headers["chatgpt-account-id"] = accountId;
  }
  const response = await fetch(`${BASE_URL}${pathname}`, { headers });
  const text = await response.text();
  const json = JSON.parse(text);
  if (!response.ok) {
    throw new Error(`GET ${pathname} failed (${response.status}): ${JSON.stringify(sanitize(json))}`);
  }
  return json;
}

function matchesExpectedClient(client) {
  if (EXPECT_CLIENT_PREFIX && !client.client_id?.startsWith(EXPECT_CLIENT_PREFIX)) {
    return false;
  }
  if (EXPECT_CLIENT_SUFFIX && !client.client_id?.endsWith(EXPECT_CLIENT_SUFFIX)) {
    return false;
  }
  return true;
}

try {
  const keyState = loadOrCreateSoftwareDeviceKey(DEVICE_KEY_PATH);
  if (keyState.created) {
    throw new Error(`No existing helper device key found at ${DEVICE_KEY_PATH}; refusing to adopt an enrollment with a new key.`);
  }
  const token = await getAuthStatusWithToken();
  const clients = await fetchJson("/wham/remote/control/clients?limit=25", token);
  const candidates = clients.items
    .filter((client) => client.enrollment_status === "enrolled_device_key")
    .filter((client) => client.display_name === "Unknown Computer")
    .filter(matchesExpectedClient)
    .sort((a, b) => String(b.last_seen_at ?? "").localeCompare(String(a.last_seen_at ?? "")));

  if (candidates.length === 0) {
    throw new Error("No matching enrolled Unknown Computer client found.");
  }
  const selected = candidates[0];
  writeEnrollment(buildEnrollmentRecord({
    accountUserId: selected.account_user_id,
    clientId: selected.client_id,
    deviceKey: keyState.deviceKey,
    source: "controller-adopt-latest",
  }), ENROLLMENT_PATH);

  console.log(JSON.stringify({
    adopted: true,
    enrollmentPath: ENROLLMENT_PATH,
    deviceKeyPath: keyState.keyPath,
    selectedClient: sanitize({
      client_id: selected.client_id,
      account_user_id: selected.account_user_id,
      enrollment_status: selected.enrollment_status,
      display_name: selected.display_name,
      last_seen_at: selected.last_seen_at,
    }),
    candidateCount: candidates.length,
    clientIdSha256Prefix: crypto.createHash("sha256").update(selected.client_id).digest("hex").slice(0, 12),
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
}
