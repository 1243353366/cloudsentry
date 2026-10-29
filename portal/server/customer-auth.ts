import type { Express, Request, Response } from "express";
import type { CustomerRepository, CustomerSessionRecord, CustomerUserRecord } from "./customer-db";
import { sdk } from "./_core/sdk";
import {
  CUSTOMER_SESSION_COOKIE,
  MANAGED_APP_SESSION_COOKIE,
  MANAGED_OAUTH_STATE_COOKIE,
  OAUTH_STATE_TTL_MS,
  SESSION_TTL_MS,
  customerSessionCookieOptions,
  decryptPrivateString,
  encryptPrivateJson,
  encryptPrivateString,
  getPrivateDataKey,
  isConfiguredTrustedOrigin,
  managedAppSessionCookieOptions,
  managedOAuthStateCookieOptions,
  managedSubjectHash,
  randomToken,
  readCookie,
  resolveTrustedRequestOrigin,
  sha256,
  timingSafeTextEqual,
} from "./customer-security";
import { trustedOrigins } from "./customer-origins";

const MANAGED_PROVIDER = "managed" as const;

type VerifiedManagedJwt = { openId: string; appId: string; name: string };
type ManagedIdentity = {
  openId: string;
  name?: unknown;
  email?: unknown;
  loginMethod?: unknown;
  platform?: unknown;
  platforms?: unknown;
};

export type CustomerAuthDependencies = {
  repository: CustomerRepository;
  now?: () => Date;
  /** Test seam for the identity lookup after the managed JWT has already verified. */
  identityFromManagedJwt?: (token: string, verified: VerifiedManagedJwt) => Promise<ManagedIdentity | null>;
  /** Test seam for the real platform code exchange and subsequent identity lookup. */
  exchangeManagedCode?: (input: { code: string; state: string }) => Promise<ManagedIdentity>;
  /** Test seam for app-session signing. Production uses the platform SDK. */
  signManagedSession?: (openId: string, name: string) => Promise<string>;
};

export type ActiveCustomerSession = { token: string; session: CustomerSessionRecord };

function responseNoStore(res: Response): Response {
  return res.set("Cache-Control", "no-store");
}

function genericError(res: Response, status: number) {
  return responseNoStore(res).status(status).json({ error: "generic" });
}

function shortQuery(req: Request, name: string, maximum = 4096): string | null {
  const value = req.query[name];
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : null;
}

function validPlatformUrl(value: string | undefined): boolean {
  if (!value || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

/** The sole customer-facing sign-in option; portal choices occur at Manus. */
export function isManagedProviderConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  if (!env.MANUS_PROJECT_ID || !validPlatformUrl(env.MANUS_OAUTH_PORTAL_URL) || !validPlatformUrl(env.MANUS_OAUTH_API_URL)) {
    return false;
  }
  if (trustedOrigins.length === 0) return false;
  try {
    getPrivateDataKey(env);
    return true;
  } catch {
    return false;
  }
}

export function customerProviderResponse() {
  return {
    providers: [{
      id: MANAGED_PROVIDER,
      name: "Managed sign-in",
      configured: isManagedProviderConfigured(),
      loginPath: "/api/auth/start/managed",
    }],
  };
}

function callbackUrl(origin: string): string {
  return `${origin}/api/auth/callback/managed`;
}

function encodeState(redirectUri: string, nonce: string): string {
  return Buffer.from(JSON.stringify({ redirectUri, nonce }), "utf8").toString("base64");
}

function decodeState(value: string): { redirectUri: string; nonce: string } | null {
  if (value.length > 4096 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64");
  } catch {
    return null;
  }
  if (decoded.toString("base64") !== value) return null;
  try {
    const parsed: unknown = JSON.parse(decoded.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const record = parsed as Record<string, unknown>;
    if (Object.keys(record).length !== 2 || typeof record.redirectUri !== "string" || typeof record.nonce !== "string") return null;
    if (record.redirectUri.length > 512 || record.nonce.length < 32 || record.nonce.length > 128) return null;
    return { redirectUri: record.redirectUri, nonce: record.nonce };
  } catch {
    return null;
  }
}

function reportedLoginMethod(identity: ManagedIdentity): string {
  const direct = [identity.loginMethod, identity.platform].find(value => typeof value === "string" && value.length > 0);
  const normalized = typeof direct === "string" ? direct.toLowerCase() : "";
  if (["google", "microsoft", "apple", "email", "passkey"].includes(normalized)) return normalized;

  const platforms = Array.isArray(identity.platforms) ? identity.platforms.filter((entry): entry is string => typeof entry === "string") : [];
  if (platforms.some(value => value.includes("GOOGLE"))) return "google";
  if (platforms.some(value => value.includes("MICROSOFT") || value.includes("AZURE"))) return "microsoft";
  if (platforms.some(value => value.includes("APPLE"))) return "apple";
  if (platforms.some(value => value.includes("PASSKEY"))) return "passkey";
  if (platforms.some(value => value.includes("EMAIL"))) return "email";
  return MANAGED_PROVIDER;
}

function normalizeIdentity(identity: ManagedIdentity, expectedOpenId?: string): { openId: string; name: string; email: string | null; loginMethod: string } | null {
  if (typeof identity.openId !== "string" || identity.openId.length < 1 || identity.openId.length > 1024 || identity.openId.startsWith("cron_")) return null;
  if (expectedOpenId && identity.openId !== expectedOpenId) return null;
  const name = typeof identity.name === "string" ? identity.name.slice(0, 512) : "";
  const email = typeof identity.email === "string" && identity.email.length <= 320 ? identity.email : null;
  return { openId: identity.openId, name, email, loginMethod: reportedLoginMethod(identity) };
}

export async function verifyManagedAppSession(token: string | undefined | null): Promise<VerifiedManagedJwt | null> {
  if (!token || token.length > 16 * 1024) return null;
  const verified = await sdk.verifySession(token);
  if (!verified || verified.openId.startsWith("cron_")) return null;
  return verified;
}

async function defaultIdentityFromManagedJwt(token: string): Promise<ManagedIdentity | null> {
  const identity = await sdk.getUserInfoWithJwt(token);
  return identity as ManagedIdentity;
}

async function defaultExchangeManagedCode(input: { code: string; state: string }): Promise<ManagedIdentity> {
  const tokens = await sdk.exchangeCodeForToken(input.code, input.state);
  return (await sdk.getUserInfo(tokens.accessToken)) as ManagedIdentity;
}

async function upsertManagedCustomer(repository: CustomerRepository, identity: ManagedIdentity, expectedOpenId?: string): Promise<CustomerUserRecord | null> {
  const normalized = normalizeIdentity(identity, expectedOpenId);
  if (!normalized) return null;
  return repository.upsertCustomerUser({
    managedSubject: managedSubjectHash(normalized.openId),
    name: normalized.name,
    email: normalized.email,
    loginMethod: normalized.loginMethod,
  });
}

async function createBoundCustomerSession(
  res: Response,
  repository: CustomerRepository,
  user: CustomerUserRecord,
  origin: string,
  now: () => Date
): Promise<ActiveCustomerSession> {
  const token = randomToken();
  const csrfToken = randomToken();
  const csrfTokenCiphertext = encryptPrivateString(csrfToken);
  const expiresAt = new Date(now().getTime() + SESSION_TTL_MS);
  await repository.createSession({
    userId: user.id,
    origin,
    tokenHash: sha256(token),
    csrfTokenHash: sha256(csrfToken),
    csrfTokenCiphertext,
    expiresAt,
  });
  res.cookie(CUSTOMER_SESSION_COOKIE, token, { ...customerSessionCookieOptions(), maxAge: SESSION_TTL_MS });
  return {
    token,
    session: {
      id: 0,
      userId: user.id,
      origin,
      tokenHash: sha256(token),
      csrfTokenHash: sha256(csrfToken),
      csrfTokenCiphertext,
      expiresAt,
      revokedAt: null,
      user,
    },
  };
}

/** Reads only the revocable, app-owned session cookie; never a bearer header. */
export async function getCustomerSession(req: Request, repository: CustomerRepository): Promise<ActiveCustomerSession | null> {
  const token = readCookie(req, CUSTOMER_SESSION_COOKIE);
  if (!token || token.length > 512) return null;
  const session = await repository.findActiveSession(sha256(token));
  return session ? { token, session } : null;
}

/**
 * Preview bootstrap: an actual signed webdev_app_session may create a private,
 * origin-bound customer session. Nothing is created for an invalid JWT or a
 * scheduled-task identity, and Authorization headers are intentionally ignored.
 */
export async function getAuthenticatedCustomerSession(
  req: Request,
  res: Response,
  dependencies: CustomerAuthDependencies
): Promise<ActiveCustomerSession | null> {
  const existing = await getCustomerSession(req, dependencies.repository);
  if (existing) return existing;

  const origin = resolveTrustedRequestOrigin(req, true);
  if (!origin) return null;
  const token = readCookie(req, MANAGED_APP_SESSION_COOKIE);
  const verified = await verifyManagedAppSession(token);
  if (!verified || !token) return null;

  const identity = await (dependencies.identityFromManagedJwt ?? defaultIdentityFromManagedJwt)(token, verified);
  const user = identity ? await upsertManagedCustomer(dependencies.repository, identity, verified.openId) : null;
  if (!user) return null;
  return createBoundCustomerSession(res, dependencies.repository, user, origin, dependencies.now ?? (() => new Date()));
}

export function clearCustomerSessionCookies(res: Response) {
  res.clearCookie(CUSTOMER_SESSION_COOKIE, customerSessionCookieOptions());
  res.clearCookie(MANAGED_APP_SESSION_COOKIE, managedAppSessionCookieOptions());
}

export function registerCustomerAuthRoutes(app: Express, dependencies: CustomerAuthDependencies) {
  const now = dependencies.now ?? (() => new Date());

  app.get("/api/auth/providers", (_req, res) => {
    responseNoStore(res).json(customerProviderResponse());
  });

  app.get("/api/auth/session", async (req, res) => {
    try {
      const active = await getAuthenticatedCustomerSession(req, res, dependencies);
      responseNoStore(res).json(active
        ? { user: active.session.user, csrfToken: decryptPrivateString(active.session.csrfTokenCiphertext) }
        : { user: null, csrfToken: null });
    } catch {
      genericError(res, 503);
    }
  });

  app.get("/api/auth/start/managed", async (req, res) => {
    if (!isManagedProviderConfigured()) {
      genericError(res, 503);
      return;
    }
    const origin = resolveTrustedRequestOrigin(req, true);
    if (!origin) {
      genericError(res, 400);
      return;
    }

    const nonce = randomToken();
    const redirectUri = callbackUrl(origin);
    const state = encodeState(redirectUri, nonce);
    try {
      await dependencies.repository.createOAuthState({
        stateHash: sha256(nonce),
        provider: MANAGED_PROVIDER,
        origin,
        nonceHash: sha256(nonce),
        // No PKCE parameter is documented for this platform contract. Store only an encrypted opaque marker.
        verifierCiphertext: encryptPrivateJson({ mode: "managed_state" }),
        expiresAt: new Date(now().getTime() + OAUTH_STATE_TTL_MS),
      });
      const portal = new URL("/app-auth", process.env.MANUS_OAUTH_PORTAL_URL);
      portal.searchParams.set("appId", process.env.MANUS_PROJECT_ID!);
      portal.searchParams.set("redirectUri", redirectUri);
      portal.searchParams.set("state", state);
      portal.searchParams.set("responseType", "code");
      res.cookie(MANAGED_OAUTH_STATE_COOKIE, nonce, { ...managedOAuthStateCookieOptions(), maxAge: OAUTH_STATE_TTL_MS });
      responseNoStore(res).redirect(302, portal.toString());
    } catch {
      genericError(res, 503);
    }
  });

  app.get("/api/auth/callback/managed", async (req, res) => {
    const code = shortQuery(req, "code");
    const encodedState = shortQuery(req, "state");
    const parsedState = encodedState ? decodeState(encodedState) : null;
    const browserNonce = readCookie(req, MANAGED_OAUTH_STATE_COOKIE);
    const fail = () => {
      res.clearCookie(MANAGED_OAUTH_STATE_COOKIE, managedOAuthStateCookieOptions());
      genericError(res, 400);
    };

    if (!code || !encodedState || !parsedState || !browserNonce || !timingSafeTextEqual(browserNonce, parsedState.nonce)) {
      fail();
      return;
    }

    try {
      const saved = await dependencies.repository.consumeOAuthState(sha256(parsedState.nonce));
      const expectedCallback = saved ? callbackUrl(saved.origin) : null;
      if (
        !saved ||
        saved.provider !== MANAGED_PROVIDER ||
        !isConfiguredTrustedOrigin(saved.origin) ||
        !expectedCallback ||
        !timingSafeTextEqual(saved.nonceHash, sha256(parsedState.nonce)) ||
        parsedState.redirectUri !== expectedCallback ||
        req.path !== "/api/auth/callback/managed"
      ) {
        fail();
        return;
      }

      // The platform SDK exchanges only after the database nonce and exact callback binding above pass.
      const rawIdentity = await (dependencies.exchangeManagedCode ?? defaultExchangeManagedCode)({ code, state: encodedState });
      const user = await upsertManagedCustomer(dependencies.repository, rawIdentity);
      if (!user) {
        fail();
        return;
      }

      const normalized = normalizeIdentity(rawIdentity);
      if (!normalized) {
        fail();
        return;
      }
      const appSession = await (dependencies.signManagedSession ?? ((openId, name) => sdk.createSessionToken(openId, { name, expiresInMs: SESSION_TTL_MS })))(normalized.openId, normalized.name);
      res.cookie(MANAGED_APP_SESSION_COOKIE, appSession, { ...managedAppSessionCookieOptions(), maxAge: SESSION_TTL_MS });
      await createBoundCustomerSession(res, dependencies.repository, user, saved.origin, now);
      res.clearCookie(MANAGED_OAUTH_STATE_COOKIE, managedOAuthStateCookieOptions());
      // Fixed in-app destination only; no client-controlled post-login URL is accepted.
      responseNoStore(res).redirect(302, "/workspace");
    } catch {
      res.clearCookie(MANAGED_OAUTH_STATE_COOKIE, managedOAuthStateCookieOptions());
      genericError(res, 503);
    }
  });
}
