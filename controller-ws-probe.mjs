#!/usr/bin/env node

import crypto from "node:crypto";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
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
const ORIGINATOR = process.env.CODEX_ORIGINATOR ?? "Codex Desktop";
const USER_AGENT = process.env.CODEX_WS_USER_AGENT ?? "Codex Desktop/26.519.81530 (Linux; arm64)";
const TIMEOUT_MS = Number(process.env.CODEX_TIMEOUT_MS ?? "5000");
const PROBE_MS = Number(process.env.CODEX_WS_PROBE_MS ?? "8000");
const SEND_INITIALIZE = process.env.CODEX_WS_SEND_INITIALIZE === "1";
const TARGET_ENV_ID = process.env.CODEX_REMOTE_ENV_ID;
const TARGET_ENV_NAME = process.env.CODEX_REMOTE_ENV_NAME;
const DEVICE_KEY_PATH = process.env.CODEX_BRIDGE_DEVICE_KEY_PATH ??
  path.join(os.homedir(), ".codex-bridge", "controller-device-key.json");
const ENROLLMENT_PATH = process.env.CODEX_BRIDGE_ENROLLMENT_PATH ?? DEFAULT_ENROLLMENT_PATH;

function apiPath(pathname) {
  return `${BASE_URL}${pathname}`;
}

function websocketUrl() {
  const base = new URL(BASE_URL);
  const ws = new URL(`${base.pathname.replace(/\/+$/u, "")}/codex/remote/control/client`, base);
  ws.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  return ws.toString();
}

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
      lowered === "keyid" ||
      lowered === "sessionid" ||
      lowered === "session_id" ||
      lowered === "env_id" ||
      lowered === "envid" ||
      lowered === "stream_id" ||
      lowered === "streamid"
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

function decodeJwtPayload(token) {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function chatgptAccountId(token) {
  const payload = decodeJwtPayload(token);
  const auth = payload?.["https://api.openai.com/auth"];
  if (!auth || typeof auth !== "object") {
    return null;
  }
  return typeof auth.chatgpt_account_id === "string"
    ? auth.chatgpt_account_id
    : typeof auth.account_id === "string"
      ? auth.account_id
      : null;
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
  const response = await fetch(apiPath(pathname), {
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
  const response = await fetch(apiPath(pathname), { headers });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return {
    path: pathname,
    method: "GET",
    status: response.status,
    contentType: response.headers.get("content-type"),
    body: json === null ? text.slice(0, 500) : sanitize(json),
    rawBody: json,
  };
}

async function selectEnvironment(authToken) {
  const environments = await fetchJson("/codex/remote/control/environments?limit=25", authToken);
  if (environments.status < 200 || environments.status >= 300) {
    throw new Error(`environments fetch failed: ${JSON.stringify(environments.body)}`);
  }
  const items = Array.isArray(environments.rawBody?.items) ? environments.rawBody.items : [];
  let candidates = items.filter((item) => item && item.online === true);
  const effectiveEnvId = TARGET_ENV_ID?.startsWith("env_") ? TARGET_ENV_ID : null;
  const effectiveEnvName = TARGET_ENV_NAME ?? (effectiveEnvId ? null : TARGET_ENV_ID);
  if (effectiveEnvId) {
    candidates = candidates.filter((item) => item.env_id === effectiveEnvId);
  }
  if (effectiveEnvName) {
    candidates = candidates.filter((item) =>
      item.display_name === effectiveEnvName ||
      item.host_name === effectiveEnvName ||
      item.name === effectiveEnvName
    );
  }
  if (candidates.length !== 1) {
    throw new Error(`Expected exactly one matching online environment; got ${candidates.length}: ${JSON.stringify(sanitize(items.map((item) => ({
      env_id: item.env_id,
      display_name: item.display_name,
      host_name: item.host_name,
      online: item.online,
      busy: item.busy,
      os: item.os,
      arch: item.arch,
      app_server_version: item.app_server_version,
    }))))}`);
  }
  delete environments.rawBody;
  return {
    env: candidates[0],
    summary: {
      query: {
        targetEnvIdProvided: Boolean(effectiveEnvId),
        targetEnvName: effectiveEnvName ?? null,
      },
      selected: sanitize({
        env_id: candidates[0].env_id,
        display_name: candidates[0].display_name,
        host_name: candidates[0].host_name,
        kind: candidates[0].kind,
        client_type: candidates[0].client_type,
        online: candidates[0].online,
        busy: candidates[0].busy,
        os: candidates[0].os,
        arch: candidates[0].arch,
        app_server_version: candidates[0].app_server_version,
      }),
      endpoint: environments,
    },
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

async function refreshClientSession({ authToken, enrollment, keyState }) {
  const start = await postJson(
    "/codex/remote/control/client/refresh/start",
    { client_id: enrollment.clientId },
    authToken,
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
    authToken,
  );
  const body = finish.rawBody;
  if (finish.status < 200 || finish.status >= 300 || typeof body?.remote_control_token !== "string") {
    throw new Error(`refresh/finish failed: ${JSON.stringify(finish.body)}`);
  }
  const tokenExpiresAt = Math.floor(Date.parse(body.expires_at) / 1000);
  if (!Number.isSafeInteger(tokenExpiresAt)) {
    throw new Error(`refresh/finish returned invalid expires_at: ${JSON.stringify(finish.body)}`);
  }
  delete start.rawBody;
  delete finish.rawBody;
  return {
    remoteControlToken: body.remote_control_token,
    tokenExpiresAt,
    scopes: Array.isArray(body.scopes) ? body.scopes : [],
    summary: {
      remoteControlToken: tokenMetadata(body.remote_control_token),
      expiresAt: body.expires_at,
      tokenExpiresAt,
      scopes: body.scopes,
      start,
      finish,
    },
  };
}

function connectionPayload(challenge) {
  return {
    type: "remoteControlClientConnection",
    nonce: challenge.nonce,
    audience: challenge.audience,
    sessionId: challenge.sessionId,
    targetOrigin: challenge.targetOrigin,
    targetPath: challenge.targetPath,
    accountUserId: challenge.accountUserId,
    clientId: challenge.clientId,
    tokenSha256Base64url: challenge.tokenSha256Base64url,
    tokenExpiresAt: challenge.tokenExpiresAt,
    scopes: challenge.scopes,
  };
}

function sameStringArray(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
}

function validateWebsocketChallenge({ challenge, wsUrl, enrollment, remoteControlToken, tokenExpiresAt, scopes }) {
  const url = new URL(wsUrl);
  const expectedOrigin = `${url.protocol === "wss:" ? "https:" : "http:"}//${url.host}`;
  const tokenHash = crypto.createHash("sha256").update(remoteControlToken, "utf8").digest("base64url");
  const errors = [];
  if (challenge.purpose !== "remote_control_client_websocket") errors.push("purpose");
  if (challenge.audience !== "remote_control_client_websocket") errors.push("audience");
  if (challenge.targetOrigin !== expectedOrigin) errors.push("targetOrigin");
  if (challenge.targetPath !== url.pathname) errors.push("targetPath");
  if (challenge.accountUserId !== enrollment.accountUserId) errors.push("accountUserId");
  if (challenge.clientId !== enrollment.clientId) errors.push("clientId");
  if (challenge.tokenSha256Base64url !== tokenHash) errors.push("tokenSha256Base64url");
  if (challenge.tokenExpiresAt !== tokenExpiresAt) errors.push("tokenExpiresAt");
  if (!sameStringArray(challenge.scopes, scopes)) errors.push("scopes");
  if (errors.length > 0) {
    throw new Error(`websocket device-key challenge validation failed: ${errors.join(", ")}`);
  }
}

function websocketProof({ challenge, keyState }) {
  const payload = connectionPayload(challenge);
  const proof = signDeviceKeyPayload(keyState.deviceKey, payload);
  return {
    payload,
    proof,
    message: {
      type: "device_key_proof",
      keyId: keyState.deviceKey.keyId,
      signatureDerBase64: proof.signatureDerBase64,
      signedPayloadBase64: proof.signedPayloadBase64,
      algorithm: keyState.deviceKey.algorithm,
    },
  };
}

function headerLine(name, value) {
  if (/[\r\n]/u.test(name) || /[\r\n]/u.test(String(value))) {
    throw new Error(`Invalid header value for ${name}`);
  }
  return `${name}: ${value}\r\n`;
}

async function openWebSocket({ url, headers }) {
  const parsed = new URL(url);
  const isTls = parsed.protocol === "wss:";
  if (!isTls && parsed.protocol !== "ws:") {
    throw new Error(`Unsupported websocket protocol: ${parsed.protocol}`);
  }
  const port = Number(parsed.port || (isTls ? 443 : 80));
  const key = crypto.randomBytes(16).toString("base64");
  const socket = isTls
    ? tls.connect({ host: parsed.hostname, port, servername: parsed.hostname })
    : net.connect({ host: parsed.hostname, port });

  await new Promise((resolve, reject) => {
    const eventName = isTls ? "secureConnect" : "connect";
    const cleanup = () => {
      socket.off(eventName, onReady);
      socket.off("error", onError);
    };
    const onReady = () => {
      cleanup();
      resolve();
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    socket.once(eventName, onReady);
    socket.once("error", onError);
  });

  let request = `GET ${parsed.pathname}${parsed.search} HTTP/1.1\r\n` +
    headerLine("Host", parsed.host) +
    headerLine("Upgrade", "websocket") +
    headerLine("Connection", "Upgrade") +
    headerLine("Sec-WebSocket-Version", "13") +
    headerLine("Sec-WebSocket-Key", key);
  for (const [name, value] of Object.entries(headers)) {
    if (value != null) {
      request += headerLine(name, value);
    }
  }
  request += "\r\n";
  socket.write(request, "utf8");

  let buffer = Buffer.alloc(0);
  const response = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for websocket upgrade response."));
    }, TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("Socket closed before websocket upgrade completed."));
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }
      const headerText = buffer.subarray(0, headerEnd).toString("utf8");
      const remaining = buffer.subarray(headerEnd + 4);
      cleanup();
      resolve({ headerText, remaining });
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });

  const lines = response.headerText.split("\r\n");
  const statusMatch = /^HTTP\/1\.[01]\s+(\d+)/u.exec(lines[0] ?? "");
  const status = statusMatch ? Number(statusMatch[1]) : null;
  const responseHeaders = {};
  for (const line of lines.slice(1)) {
    const index = line.indexOf(":");
    if (index !== -1) {
      responseHeaders[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
    }
  }
  if (status !== 101) {
    socket.destroy();
    throw new Error(`websocket upgrade failed (${status ?? "unknown"}): ${response.remaining.toString("utf8").slice(0, 500)}`);
  }
  const expectedAccept = crypto
    .createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "utf8")
    .digest("base64");
  if (responseHeaders["sec-websocket-accept"] !== expectedAccept) {
    socket.destroy();
    throw new Error("websocket upgrade response had invalid Sec-WebSocket-Accept.");
  }
  return {
    socket,
    remaining: response.remaining,
    status,
    responseHeaders: sanitize({
      upgrade: responseHeaders.upgrade,
      connection: responseHeaders.connection,
      server: responseHeaders.server,
    }),
  };
}

function encodeClientFrame(opcode, payload = Buffer.alloc(0)) {
  const mask = crypto.randomBytes(4);
  const length = payload.length;
  let headerLength = 2;
  if (length >= 126 && length <= 0xffff) {
    headerLength += 2;
  } else if (length > 0xffff) {
    headerLength += 8;
  }
  const frameBuffer = Buffer.alloc(headerLength + 4 + length);
  frameBuffer[0] = 0x80 | opcode;
  let offset = 2;
  if (length < 126) {
    frameBuffer[1] = 0x80 | length;
  } else if (length <= 0xffff) {
    frameBuffer[1] = 0x80 | 126;
    frameBuffer.writeUInt16BE(length, offset);
    offset += 2;
  } else {
    frameBuffer[1] = 0x80 | 127;
    frameBuffer.writeBigUInt64BE(BigInt(length), offset);
    offset += 8;
  }
  mask.copy(frameBuffer, offset);
  offset += 4;
  for (let index = 0; index < length; index += 1) {
    frameBuffer[offset + index] = payload[index] ^ mask[index % 4];
  }
  return frameBuffer;
}

function decodeServerFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let cursor = offset + 2;
    if (length === 126) {
      if (buffer.length - cursor < 2) break;
      length = buffer.readUInt16BE(cursor);
      cursor += 2;
    } else if (length === 127) {
      if (buffer.length - cursor < 8) break;
      const bigLength = buffer.readBigUInt64BE(cursor);
      if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("websocket frame is too large.");
      }
      length = Number(bigLength);
      cursor += 8;
    }
    let mask = null;
    if (masked) {
      if (buffer.length - cursor < 4) break;
      mask = buffer.subarray(cursor, cursor + 4);
      cursor += 4;
    }
    if (buffer.length - cursor < length) break;
    const payload = Buffer.from(buffer.subarray(cursor, cursor + length));
    if (mask) {
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    frames.push({ fin, opcode, payload });
    offset = cursor + length;
  }
  return { frames, remaining: buffer.subarray(offset) };
}

function summarizeMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return { kind: typeof message };
  }
  const out = {
    type: message.type ?? null,
    keys: Object.keys(message).sort(),
  };
  for (const key of ["client_id", "clientId", "env_id", "envId", "stream_id", "streamId", "sessionId"]) {
    if (message[key] != null) {
      out[key] = sanitize(message[key], key);
    }
  }
  for (const key of ["seq_id", "status", "purpose", "audience", "targetOrigin", "targetPath", "tokenExpiresAt"]) {
    if (message[key] != null) {
      out[key] = sanitize(message[key], key);
    }
  }
  if (Array.isArray(message.scopes)) {
    out.scopes = message.scopes;
  }
  if (message.cursor != null) {
    out.cursorPresent = true;
  }
  if (message.message && typeof message.message === "object") {
    out.message = {
      jsonrpc: message.message.jsonrpc ?? null,
      method: message.message.method ?? null,
      id: message.message.id ?? null,
      hasResult: Object.hasOwn(message.message, "result"),
      hasError: Object.hasOwn(message.message, "error"),
    };
  }
  return out;
}

function initializeJsonRpc() {
  return {
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
}

function clientMessageEnvelope({ enrollment, envId, streamId, seqId, message }) {
  return {
    type: "client_message",
    client_id: enrollment.clientId,
    env_id: envId,
    stream_id: streamId,
    seq_id: seqId,
    skip_history: false,
    message,
  };
}

function clientClosedEnvelope({ enrollment, envId, streamId, seqId }) {
  return {
    type: "client_closed",
    client_id: enrollment.clientId,
    env_id: envId,
    stream_id: streamId,
    seq_id: seqId,
  };
}

async function runWebsocketProbe({
  authToken,
  enrollment,
  keyState,
  remoteControlToken,
  tokenExpiresAt,
  scopes,
  targetEnv,
}) {
  const wsUrl = websocketUrl();
  const accountId = ACCOUNT_ID ?? chatgptAccountId(authToken);
  const requestHeaders = {
    Authorization: `Bearer ${authToken}`,
    ...(accountId ? { "ChatGPT-Account-Id": accountId } : {}),
    originator: ORIGINATOR,
    "User-Agent": USER_AGENT,
    "x-codex-client-id": enrollment.clientId,
    "x-codex-protocol-version": "3",
    "x-codex-client-session-token": `Bearer ${remoteControlToken}`,
  };
  const opened = await openWebSocket({ url: wsUrl, headers: requestHeaders });
  const socket = opened.socket;
  const events = [];
  let buffer = opened.remaining;
  let challengeReceived = false;
  let challengeAuthorized = false;
  let challengeSummary = null;
  let proofSummary = null;
  let closeFrame = null;
  let streamId = null;
  let nextSeqId = 1;
  let initializeSent = false;
  let initializeResponseReceived = false;
  let clientClosedSent = false;
  let settled = false;
  let finishTimer = null;
  const outbound = [];

  const sendText = (value) => {
    socket.write(encodeClientFrame(0x1, Buffer.from(value, "utf8")));
  };
  const sendJson = (message, purpose) => {
    sendText(JSON.stringify(message));
    outbound.push({ purpose, message: summarizeMessage(message) });
  };
  const sendPong = (payload) => {
    socket.write(encodeClientFrame(0x0a, payload));
  };
  const sendInitialize = () => {
    if (!targetEnv || initializeSent) {
      return;
    }
    streamId = crypto.randomUUID();
    const envelope = clientMessageEnvelope({
      enrollment,
      envId: targetEnv.env_id,
      streamId,
      seqId: nextSeqId,
      message: initializeJsonRpc(),
    });
    nextSeqId += 1;
    initializeSent = true;
    sendJson(envelope, "initialize");
  };
  const sendClientClosed = () => {
    if (!targetEnv || !streamId || clientClosedSent) {
      return;
    }
    const envelope = clientClosedEnvelope({
      enrollment,
      envId: targetEnv.env_id,
      streamId,
      seqId: nextSeqId,
    });
    nextSeqId += 1;
    clientClosedSent = true;
    sendJson(envelope, "client_closed");
  };

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(), PROBE_MS);
    const cleanup = () => {
      settled = true;
      clearTimeout(timeout);
      if (finishTimer) {
        clearTimeout(finishTimer);
        finishTimer = null;
      }
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const finish = () => {
      if (settled) {
        return;
      }
      cleanup();
      resolve();
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      finish();
    };
    const processBuffer = () => {
      const decoded = decodeServerFrames(buffer);
      buffer = decoded.remaining;
      for (const item of decoded.frames) {
        if (item.opcode === 0x1) {
          const text = item.payload.toString("utf8");
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = null;
          }
          events.push({ opcode: "text", fin: item.fin, bytes: item.payload.length, message: summarizeMessage(parsed) });
          if (parsed?.type === "device_key_challenge") {
            challengeReceived = true;
            validateWebsocketChallenge({
              challenge: parsed,
              wsUrl,
              enrollment,
              remoteControlToken,
              tokenExpiresAt,
              scopes,
            });
            const signed = websocketProof({ challenge: parsed, keyState });
            sendText(JSON.stringify(signed.message));
            challengeAuthorized = true;
            challengeSummary = summarizeMessage(parsed);
            proofSummary = {
              signatureDerLength: signed.proof.signatureDerLength,
              verified: signed.proof.verified,
              signedPayload: sanitize(signed.payload),
            };
            sendInitialize();
          } else if (
            parsed?.type === "server_message" &&
            streamId != null &&
            parsed.stream_id === streamId &&
            parsed.message?.id === 1
          ) {
            initializeResponseReceived = true;
            sendClientClosed();
            finishTimer ??= setTimeout(() => finish(), 500);
          }
        } else if (item.opcode === 0x8) {
          const code = item.payload.length >= 2 ? item.payload.readUInt16BE(0) : null;
          const reason = item.payload.length > 2 ? item.payload.subarray(2).toString("utf8") : "";
          closeFrame = { code, reason: reason.slice(0, 200) };
          finish();
          return;
        } else if (item.opcode === 0x9) {
          events.push({ opcode: "ping", bytes: item.payload.length });
          sendPong(item.payload);
        } else if (item.opcode === 0x0a) {
          events.push({ opcode: "pong", bytes: item.payload.length });
        } else {
          events.push({ opcode: item.opcode, fin: item.fin, bytes: item.payload.length });
        }
      }
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      processBuffer();
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
    processBuffer();
  }).finally(() => {
    socket.end(encodeClientFrame(0x8));
    socket.destroy();
  });

  return {
    wsUrl,
    requestHeaderNames: Object.keys(requestHeaders).sort(),
    accountHeaderProvided: Boolean(accountId),
    originator: ORIGINATOR,
    userAgent: USER_AGENT,
    upgrade: {
      status: opened.status,
      responseHeaders: opened.responseHeaders,
    },
    challengeReceived,
    challengeAuthorized,
    challenge: challengeSummary,
    proof: proofSummary,
    targetEnv: targetEnv ? sanitize({
      env_id: targetEnv.env_id,
      display_name: targetEnv.display_name,
      host_name: targetEnv.host_name,
      online: targetEnv.online,
      busy: targetEnv.busy,
      os: targetEnv.os,
      arch: targetEnv.arch,
      app_server_version: targetEnv.app_server_version,
    }) : null,
    initializeSent,
    initializeResponseReceived,
    clientClosedSent,
    outbound,
    closeFrame,
    eventCount: events.length,
    events,
  };
}

try {
  const keyState = loadOrCreateSoftwareDeviceKey(DEVICE_KEY_PATH);
  const enrollment = readEnrollment(ENROLLMENT_PATH);
  if (keyState.created) {
    throw new Error(`No existing helper device key found at ${DEVICE_KEY_PATH}; refusing websocket probe with a new key.`);
  }
  if (enrollment.keyId !== keyState.deviceKey.keyId) {
    throw new Error("Enrollment keyId does not match local device key.");
  }
  const auth = await getAuthStatusWithToken();
  const refreshed = await refreshClientSession({
    authToken: auth.token,
    enrollment,
    keyState,
  });
  const selectedEnvironment = SEND_INITIALIZE ? await selectEnvironment(auth.token) : null;
  const websocket = await runWebsocketProbe({
    authToken: auth.token,
    enrollment,
    keyState,
    remoteControlToken: refreshed.remoteControlToken,
    tokenExpiresAt: refreshed.tokenExpiresAt,
    scopes: refreshed.scopes,
    targetEnv: selectedEnvironment?.env ?? null,
  });

  console.log(JSON.stringify({
    stateChange: "client-websocket-probe",
    baseUrl: BASE_URL,
    enrollmentPath: ENROLLMENT_PATH,
    deviceKeyPath: keyState.keyPath,
    appServer: auth.appServer,
    authToken: tokenMetadata(auth.token),
    refresh: refreshed.summary,
    environment: selectedEnvironment?.summary ?? null,
    websocket,
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
}
