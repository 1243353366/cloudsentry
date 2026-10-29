import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { CookieOptions, Request } from "express";
import { parse as parseCookieHeader } from "cookie";
import { isTrustedOrigin, trustedOrigins } from "./customer-origins";

export const CUSTOMER_SESSION_COOKIE = "CS_operator_session";
export const MANAGED_OAUTH_STATE_COOKIE = "__Host-cs_managed_state";
export const MANAGED_APP_SESSION_COOKIE = "webdev_app_session";
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
export const MAX_PRIVATE_JSON_BYTES = 1024 * 1024;

const PRIVATE_DATA_INFO = "cloudsentry/keyless/private-data/v1";
const MANAGED_SUBJECT_INFO = "cloudsentry/keyless/managed-subject/v1";

export class PrivateDataKeyUnavailableError extends Error {
  constructor() {
    super("private data key unavailable");
  }
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function timingSafeTextEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function customerSessionCookieOptions(): CookieOptions {
  // Preview is externally HTTPS in a cross-site iframe even when Node receives HTTP.
  return { httpOnly: true, path: "/", sameSite: "none", secure: true };
}

export function managedOAuthStateCookieOptions(): CookieOptions {
  // __Host- requires Secure, Path=/, and no Domain, preventing sibling-host planting.
  return { httpOnly: true, path: "/", sameSite: "none", secure: true };
}

export function managedAppSessionCookieOptions(): CookieOptions {
  return { httpOnly: true, path: "/", sameSite: "none", secure: true };
}

export function readCookie(req: Request, name: string): string | undefined {
  return parseCookieHeader(req.headers.cookie ?? "")[name];
}

export function normalizeHttpsOrigin(value: string | undefined): string | null {
  if (!value || value.length > 255 || /[\u0000-\u001f\u007f\s]/.test(value)) return null;
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      parsed.origin !== value
    ) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function refererOrigin(value: string | undefined): string | null {
  if (!value || value.length > 4096) return null;
  try {
    return normalizeHttpsOrigin(new URL(value).origin);
  } catch {
    return null;
  }
}

function queryOrigin(req: Request): string | null | "invalid" {
  const value = req.query.origin;
  if (value === undefined) return null;
  if (typeof value !== "string") return "invalid";
  return normalizeHttpsOrigin(value) ?? "invalid";
}

/**
 * Resolve only an exact, code-owned browser origin. A query origin is merely a
 * selector among those literals; it is never accepted unless it is allowlisted.
 */
export function resolveTrustedRequestOrigin(req: Request, allowSingleConfiguredOrigin: boolean): string | null {
  const candidates: string[] = [];
  const requested = queryOrigin(req);
  if (requested === "invalid") return null;
  if (requested) candidates.push(requested);

  const originHeader = req.get("origin");
  if (originHeader !== undefined) {
    const parsed = normalizeHttpsOrigin(originHeader);
    if (!parsed) return null;
    candidates.push(parsed);
  }

  const refererHeader = req.get("referer");
  if (refererHeader !== undefined) {
    const parsed = refererOrigin(refererHeader);
    if (!parsed) return null;
    candidates.push(parsed);
  }

  if (candidates.length > 0) {
    const distinct = [...new Set(candidates)];
    if (distinct.length !== 1 || !isTrustedOrigin(distinct[0]!)) return null;
    return distinct[0]!;
  }

  return allowSingleConfiguredOrigin && trustedOrigins.length === 1 ? trustedOrigins[0]! : null;
}

export function isConfiguredTrustedOrigin(origin: string): boolean {
  return isTrustedOrigin(origin);
}

export function hasExpectedExternalOrigin(req: Request, expectedOrigin: string): boolean {
  const supplied = normalizeHttpsOrigin(req.get("origin"));
  return supplied !== null && supplied === expectedOrigin && isTrustedOrigin(expectedOrigin);
}

/**
 * Derive one 256-bit private-data key from the platform signing secret. It is
 * domain-separated from application JWT signing and salted per project; no
 * customer, builder, or separately configured vault key is accepted.
 */
export function getPrivateDataKey(env: NodeJS.ProcessEnv = process.env): Buffer {
  const secret = env.MANUS_JWT_SECRET;
  const projectId = env.MANUS_PROJECT_ID;
  if (!secret || !projectId || secret.length > 16 * 1024 || projectId.length > 1024) {
    throw new PrivateDataKeyUnavailableError();
  }
  return Buffer.from(
    hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.from(projectId, "utf8"), Buffer.from(PRIVATE_DATA_INFO, "utf8"), 32)
  );
}

export function privateJsonString(value: unknown, maxBytes = MAX_PRIVATE_JSON_BYTES): string {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error("invalid private JSON");
  }
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes) {
    throw new Error("private JSON exceeds limit");
  }
  return serialized;
}

export function encryptPrivateString(value: string, key = getPrivateDataKey()): string {
  if (Buffer.byteLength(value, "utf8") > MAX_PRIVATE_JSON_BYTES) throw new Error("private payload exceeds limit");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v2.${iv.toString("base64url")}.${tag.toString("base64url")}.${ciphertext.toString("base64url")}`;
}

export function decryptPrivateString(envelope: string, key = getPrivateDataKey()): string {
  const parts = envelope.split(".");
  if (parts.length !== 4 || parts[0] !== "v2" || parts.some(part => part.length > 2 * MAX_PRIVATE_JSON_BYTES)) {
    throw new Error("invalid encrypted payload");
  }
  try {
    const iv = Buffer.from(parts[1]!, "base64url");
    const tag = Buffer.from(parts[2]!, "base64url");
    const ciphertext = Buffer.from(parts[3]!, "base64url");
    if (iv.length !== 12 || tag.length !== 16 || ciphertext.length > MAX_PRIVATE_JSON_BYTES) {
      throw new Error("invalid encrypted payload");
    }
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length > MAX_PRIVATE_JSON_BYTES) throw new Error("invalid encrypted payload");
    return plaintext.toString("utf8");
  } catch {
    throw new Error("invalid encrypted payload");
  }
}

export function encryptPrivateJson(value: unknown): string {
  return encryptPrivateString(privateJsonString(value));
}

export function decryptPrivateJson<T>(envelope: string): T {
  const plaintext = decryptPrivateString(envelope);
  try {
    return JSON.parse(plaintext) as T;
  } catch {
    throw new Error("invalid encrypted payload");
  }
}

/** A stable, project-scoped identifier namespace; email is never part of it. */
export function managedSubjectHash(subject: string, env: NodeJS.ProcessEnv = process.env): string {
  const projectId = env.MANUS_PROJECT_ID;
  if (!projectId || !subject || subject.startsWith("cron_")) throw new Error("invalid managed subject");
  return createHash("sha256")
    .update(MANAGED_SUBJECT_INFO)
    .update("\u0000")
    .update(projectId)
    .update("\u0000")
    .update(subject)
    .digest("hex");
}
