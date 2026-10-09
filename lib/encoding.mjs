import { Buffer } from "node:buffer";

export function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

export function base64url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function utf8Bytes(value) {
  return Buffer.from(value, "utf8");
}

export function stableJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }

  const fields = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`);
  return `{${fields.join(",")}}`;
}

