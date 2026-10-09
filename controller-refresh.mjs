#!/usr/bin/env node

import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  deviceIdentityHash,
  loadOrCreateSoftwareDeviceKey,
  signDeviceKeyPayload,
} from "./lib/device-key.mjs";
import {
  DEFAULT_ENROLLMENT_PATH,
  readEnrollment,
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
      lowered.includes("nonce") ||
      lowered.includes("signature") ||
      lowered.includes("signed_payload") ||
      lowered.includes("signedpayload") ||
      lowered.includes("public_key") ||
      lowered.includes("publickey") ||
      lowered.includes("identity_hash") ||
      lowered.includes("identityhash") ||
      lowered.includes("sha256") ||
      lowered.includes("account_user_id") ||
      lowered.includes("accountuserid") ||
      lowered === "user_id"
    ) {
      return redactString(value, false);
    }
    if (
      lowered.endsWith("_id") ||
      lowered.endsWith("id") ||
      lowered === "id" ||
      lowered === "client_id" ||
      lowered === "clientid" ||
      lowered === "challenge_id" ||
      lowered === "challengeid" ||
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

function tokenMetadata(token) {
  return {
    received: Boolean(token),
    length: token.length,
    sha256Prefix: crypto.createHash("sha256").update(token).digest("hex").slice(0, 12),
    looksLikeJwt: token.split(".").length === 3,
  };
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
  return {
    token,
    appServer: {
      command: `${CODEX_BIN} ${CODEX_ARGS.join(" ")}`,
      stderr: stderr.trim() || null,
      timedOut,
    },
  };
}

async function postJson(pathname, body, token) {
  const accountId = ACCOUNT_ID ?? chatgptAccountId(token);
  const headers = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    "user-agent": "codex-bridge-helper/0.1",
  };
  if (accountId) {
    headers["chatgpt-account-id"] = accountId;
  }
  const response = await fetch(`${BASE_URL}${pathname}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return {
    path: pathname,
    method: "POST",
    requestBody: sanitize(body),
    status: response.status,
    contentType: response.headers.get("content-type"),
    body: json === null ? text.slice(0, 500) : sanitize(json),
    rawBody: json,
  };
}

function refreshPayload(enrollment, challenge, identityHash) {
  return {
    type: "remoteControlClientEnrollment",
    nonce: challenge.nonce,
    audience: challenge.audience,
    challengeId: challenge.challenge_id,
    targetOrigin: challenge.target_origin,
    targetPath: challenge.target_path,
    accountUserId: enrollment.accountUserId,
    clientId: enrollment.clientId,
    deviceIdentitySha256Base64url: challenge.device_identity_hash ?? identityHash,
    challengeExpiresAt: challenge.challenge_expires_at,
  };
}

try {
  const keyState = loadOrCreateSoftwareDeviceKey(DEVICE_KEY_PATH);
  const enrollment = readEnrollment(ENROLLMENT_PATH);
  if (enrollment.keyId !== keyState.deviceKey.keyId) {
    throw new Error("Enrollment keyId does not match local device key.");
  }
  const auth = await getAuthStatusWithToken();

  const start = await postJson(
    "/codex/remote/control/client/refresh/start",
    { client_id: enrollment.clientId },
    auth.token,
  );
  if (start.status < 200 || start.status >= 300) {
    throw new Error(`refresh/start failed: ${JSON.stringify(start.body)}`);
  }
  const challenge = start.rawBody?.device_key_challenge;
  if (!challenge) {
    throw new Error(`refresh/start returned no challenge: ${JSON.stringify(start.body)}`);
  }
  const identityHash = deviceIdentityHash(keyState.deviceKey);
  const signedPayload = refreshPayload(enrollment, challenge, identityHash);
  const proof = signDeviceKeyPayload(keyState.deviceKey, signedPayload);
  const finishBody = {
    client_id: enrollment.clientId,
    device_key_proof: {
      challenge_token: challenge.challenge_token,
      key_id: keyState.deviceKey.keyId,
      signature_der_base64: proof.signatureDerBase64,
      signed_payload_base64: proof.signedPayloadBase64,
      algorithm: keyState.deviceKey.algorithm,
    },
  };

  const finish = await postJson(
    "/codex/remote/control/client/refresh/finish",
    finishBody,
    auth.token,
  );
  const remoteControlToken = finish.rawBody?.remote_control_token;
  delete start.rawBody;
  delete finish.rawBody;

  console.log(JSON.stringify({
    stateChange: "client-refresh",
    baseUrl: BASE_URL,
    accountHeaderProvided: Boolean(ACCOUNT_ID ?? chatgptAccountId(auth.token)),
    enrollmentPath: ENROLLMENT_PATH,
    deviceKeyPath: keyState.keyPath,
    appServer: auth.appServer,
    token: tokenMetadata(auth.token),
    signedPayload: sanitize(signedPayload),
    proof: {
      signatureDerLength: proof.signatureDerLength,
      verified: proof.verified,
    },
    remoteControlToken: typeof remoteControlToken === "string" ? tokenMetadata(remoteControlToken) : null,
    start,
    finish,
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
}
