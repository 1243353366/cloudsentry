import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import express from "express";
import type { CustomerRepository, CustomerScanRecord, CustomerSessionRecord } from "./customer-db";
import {
  customerProviderResponse,
  registerCustomerAuthRoutes,
  verifyManagedAppSession,
} from "./customer-auth";
import { registerCustomerApiRoutes } from "./customer-api";
import { PREVIEW_ORIGIN } from "./customer-origins";
import { decryptPrivateJson, encryptPrivateJson, encryptPrivateString, getPrivateDataKey, sha256 } from "./customer-security";
import { sdk } from "./_core/sdk";

const ORIGIN = PREVIEW_ORIGIN;
const SESSION_TOKEN = "operator-session-token";
const CSRF_TOKEN = "csrf-token-for-test";

function sampleSession(ownerId = 7): CustomerSessionRecord {
  return {
    id: 1,
    userId: ownerId,
    origin: ORIGIN,
    tokenHash: sha256(SESSION_TOKEN),
    csrfTokenHash: sha256(CSRF_TOKEN),
    csrfTokenCiphertext: encryptPrivateString(CSRF_TOKEN),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    revokedAt: null,
    user: { id: ownerId, provider: "passkey", name: "Customer", email: "customer@example.test" },
  };
}

function sampleScan(ownerId = 7): CustomerScanRecord {
  return {
    id: 44,
    ownerId,
    connectionId: null,
    provider: "local",
    status: "completed",
    connectionLabel: null,
    reportCiphertext: encryptPrivateJson({
      provider: "local",
      source_context: { canonical_original_sha256: "a".repeat(64), supplied_scope: "workstation", supplied_since_utc: null, supplied_until_utc: null },
      sanitized_representation: { networks: ["192.0.2.0/24"], token: "[redacted]" },
    }),
    summaryCiphertext: null,
    createdAt: new Date("2026-10-29T22:00:00Z"),
  };
}

function repository(overrides: Partial<CustomerRepository> = {}): CustomerRepository {
  const session = sampleSession();
  return {
    upsertCustomerUser: vi.fn(async input => ({ id: 7, provider: input.loginMethod, name: input.name, email: input.email })),
    createOAuthState: vi.fn(),
    consumeOAuthState: vi.fn(async () => null),
    createSession: vi.fn(),
    findActiveSession: vi.fn(async hash => hash === session.tokenHash ? session : null),
    revokeSession: vi.fn(),
    revokeAllSessions: vi.fn(),
    createProfile: vi.fn(async input => ({ ...input, id: 19, createdAt: new Date("2026-10-29T22:00:00Z") })),
    countProfiles: vi.fn(async () => 0),
    listProfiles: vi.fn(async () => []),
    findOwnedProfile: vi.fn(async () => null),
    deleteOwnedProfile: vi.fn(async () => false),
    createScan: vi.fn(async input => ({ ...input, id: 45, summaryCiphertext: null, createdAt: new Date() })),
    countScans: vi.fn(async () => 0),
    listScans: vi.fn(async () => []),
    findOwnedScan: vi.fn(async () => null),
    saveOwnedSummary: vi.fn(async () => true),
    ...overrides,
  };
}

function appWith(repo: CustomerRepository) {
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  const auth = { repository: repo };
  registerCustomerAuthRoutes(app, auth);
  registerCustomerApiRoutes(app, { repository: repo, authDependencies: auth });
  return app;
}

async function request(app: express.Express, path: string, init: RequestInit = {}) {
  const server = await new Promise<ReturnType<express.Express["listen"]>>(resolve => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test listener unavailable");
  try {
    return await fetch(`http://127.0.0.1:${address.port}${path}`, { redirect: "manual", ...init });
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

function authHeaders(extra: HeadersInit = {}): HeadersInit {
  return {
    Cookie: `CS_operator_session=${SESSION_TOKEN}`,
    Origin: ORIGIN,
    "X-CSRF-Token": CSRF_TOKEN,
    "Content-Type": "application/json",
    ...extra,
  };
}

beforeEach(() => {
  vi.stubEnv("MANUS_PROJECT_ID", "project-test");
  vi.stubEnv("MANUS_JWT_SECRET", "unit-test-signing-key-never-deployed");
  vi.stubEnv("MANUS_OAUTH_PORTAL_URL", "https://manus.im");
  vi.stubEnv("MANUS_OAUTH_API_URL", "https://oauth.example.test");
});
afterEach(() => vi.unstubAllEnvs());

describe("managed keyless customer boundary", () => {
  it("derives private data encryption from the managed project secret and project ID", () => {
    const first = getPrivateDataKey();
    vi.stubEnv("MANUS_PROJECT_ID", "different-project");
    const second = getPrivateDataKey();
    expect(first.equals(second)).toBe(false);
  });

  it("advertises exactly one honest managed sign-in option and no direct GitHub route", async () => {
    expect(customerProviderResponse()).toEqual({
      providers: [{ id: "managed", name: "Managed sign-in", configured: true, loginPath: "/api/auth/start/managed" }],
    });
    const response = await request(appWith(repository()), "/api/auth/start/github");
    expect(response.status).toBe(404);
  });

  it("rejects credential-shaped labels and regions without writing a provider profile", async () => {
    for (const metadata of [
      { label: `AKIA${"Z".repeat(16)}`, region: "us-east-1" },
      { label: "Personal account", region: "Bearer NOT-A-REAL-TOKEN" },
      { label: "token=NOT-A-REAL-TOKEN", region: "us-east-1" },
    ]) {
      const repo = repository();
      const response = await request(appWith(repo), "/api/profiles", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ provider: "aws", scopeId: "123456789012", ...metadata }),
      });
      expect(response.status).toBe(400);
      expect(repo.createProfile).not.toHaveBeenCalled();
    }
  });

  it("validates a signed Manus app JWT with matching app ID and expiry, not a fake preview identity", async () => {
    const token = await sdk.signSession({ openId: "managed-user", appId: "project-test", name: "Customer" }, { expiresInMs: 60_000 });
    expect(await verifyManagedAppSession(token)).toMatchObject({ openId: "managed-user", appId: "project-test" });
    vi.stubEnv("MANUS_PROJECT_ID", "other-project");
    expect(await verifyManagedAppSession(token)).toBeNull();
    vi.stubEnv("MANUS_PROJECT_ID", "project-test");
    const expired = await sdk.signSession({ openId: "managed-user", appId: "project-test", name: "Customer" }, { expiresInMs: -1_000 });
    expect(await verifyManagedAppSession(expired)).toBeNull();
  });

  it("does not invent a user when no signed managed or bound customer session exists", async () => {
    const repo = repository();
    const response = await request(appWith(repo), "/api/auth/session", { headers: { Referer: `${ORIGIN}/` } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ user: null, csrfToken: null });
    expect(repo.upsertCustomerUser).not.toHaveBeenCalled();
  });

  it("rejects malformed callback state even when a state cookie is present", async () => {
    const repo = repository();
    const app = appWith(repo);
    const started = await request(app, `/api/auth/start/managed?origin=${encodeURIComponent(ORIGIN)}`);
    expect(started.status).toBe(302);
    const cookie = started.headers.get("set-cookie");
    expect(cookie).toContain("__Host-cs_managed_state=");
    const response = await request(app, "/api/auth/callback/managed?code=code&state=not-base64", {
      headers: { Cookie: cookie?.split(";")[0] ?? "" },
    });
    expect(response.status).toBe(400);
    expect(repo.consumeOAuthState).not.toHaveBeenCalled();

    const destination = new URL(started.headers.get("location")!);
    const originalState = destination.searchParams.get("state")!;
    const parsed = JSON.parse(Buffer.from(originalState, "base64").toString("utf8")) as { redirectUri: string; nonce: string };
    const mismatchedState = Buffer.from(JSON.stringify({ ...parsed, nonce: "x".repeat(parsed.nonce.length) }), "utf8").toString("base64");
    const nonceMismatch = await request(app, `/api/auth/callback/managed?code=code&state=${encodeURIComponent(mismatchedState)}`, {
      headers: { Cookie: cookie?.split(";")[0] ?? "" },
    });
    expect(nonceMismatch.status).toBe(400);
    expect(repo.consumeOAuthState).not.toHaveBeenCalled();
  });

  it("refuses credential-shaped profile bodies and never creates an authenticated cloud connection", async () => {
    const repo = repository();
    const response = await request(appWith(repo), "/api/profiles", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ provider: "cloudflare", label: "Production", scopeId: "a".repeat(32), token: "must-not-be-accepted" }),
    });
    expect(response.status).toBe(400);
    expect(repo.createProfile).not.toHaveBeenCalled();
  });

  it("stores an encrypted metadata-only profile marker with manual_profile status", async () => {
    const repo = repository();
    const response = await request(appWith(repo), "/api/connections", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ provider: "render", label: "Customer Render", scopeId: "tea-workspace1" }),
    });
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ status: "manual_profile", provider: "render" });
    expect(repo.createProfile).toHaveBeenCalledWith(expect.objectContaining({
      profileMarkerCiphertext: expect.any(String),
    }));
    const marker = (repo.createProfile as ReturnType<typeof vi.fn>).mock.calls[0]?.[0].profileMarkerCiphertext;
    expect(decryptPrivateJson(marker)).toEqual({ mode: "metadata_only" });
  });

  it("rejects obsolete cloud scan execution even for an authenticated customer", async () => {
    const response = await request(appWith(repository()), "/api/scans", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ consent: true }),
    });
    expect(response.status).toBe(410);
    expect(await response.json()).toEqual({ error: "manual_import_required" });
  });

  it("sanitizes imported evidence, preserves only a canonical original digest, and does not auto-generate a summary", async () => {
    const created = vi.fn(async input => ({ ...input, id: 45, summaryCiphertext: null, createdAt: new Date() }));
    const repo = repository({ createScan: created });
    const imported = await request(appWith(repo), "/api/scans/import", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ consent: true, provider: "local", report: { networks: ["192.0.2.0/24"], password: "secret-value", nested: { apiToken: "also-secret" } } }),
    });
    expect(imported.status).toBe(201);
    const body = await imported.json();
    expect(JSON.stringify(body)).not.toContain("secret-value");
    expect(JSON.stringify(body)).not.toContain("also-secret");
    const saved = decryptPrivateJson<Record<string, unknown>>(created.mock.calls[0]?.[0].reportCiphertext);
    expect(saved.source_context).toMatchObject({ original_representation_retained: false, canonical_original_sha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(saved.sanitized_representation).toMatchObject({ password: "[redacted]", nested: { apiToken: "[redacted]" } });

    const scan = sampleScan();
    const summaryRepo = repository({ findOwnedScan: vi.fn(async () => scan) });
    const detail = await request(appWith(summaryRepo), "/api/scans/44", { headers: { Cookie: `CS_operator_session=${SESSION_TOKEN}` } });
    expect(detail.status).toBe(200);
    expect((await detail.json()).summary).toBeUndefined();
    const denied = await request(appWith(summaryRepo), "/api/scans/44/summary", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ consent: false }),
    });
    expect(denied.status).toBe(400);
    expect(summaryRepo.saveOwnedSummary).not.toHaveBeenCalled();
  });

  it("enforces the exact bound origin and owner predicates for private records", async () => {
    const repo = repository({ findOwnedScan: vi.fn(async () => null) });
    const hostile = await request(appWith(repo), "/api/profiles", {
      method: "POST",
      headers: authHeaders({ Origin: "https://attacker.example" }),
      body: JSON.stringify({ provider: "render", label: "Nope", scopeId: "tea-workspace1" }),
    });
    expect(hostile.status).toBe(403);
    expect(repo.createProfile).not.toHaveBeenCalled();
    const hidden = await request(appWith(repo), "/api/scans/44", { headers: { Cookie: `CS_operator_session=${SESSION_TOKEN}` } });
    expect(hidden.status).toBe(404);
    expect(repo.findOwnedScan).toHaveBeenCalledWith(7, 44);
  });
});
