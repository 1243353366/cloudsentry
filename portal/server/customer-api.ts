import type { Express, Request, Response } from "express";
import type {
  CustomerAuthDependencies,
  ActiveCustomerSession,
} from "./customer-auth";
import { clearCustomerSessionCookies, getAuthenticatedCustomerSession } from "./customer-auth";
import type {
  CustomerProfileProvider,
  CustomerRepository,
  CustomerScanProvider,
  CustomerScanRecord,
} from "./customer-db";
import {
  decryptPrivateJson,
  decryptPrivateString,
  encryptPrivateJson,
  hasExpectedExternalOrigin,
  privateJsonString,
  sha256,
  timingSafeTextEqual,
} from "./customer-security";
import { reviewNetworkBoundaries } from "./network-boundary";
import { selectedTextIndicators } from "./import-indicators";
import { containsCredentialLikeValue } from "./sensitive-values";

const PROFILE_PROVIDERS = ["cloudflare", "aws", "render", "railway"] as const;
const IMPORT_PROVIDERS = [...PROFILE_PROVIDERS, "local"] as const;
const MAX_PROFILES_PER_CUSTOMER = 20;
const MAX_IMPORTS_PER_CUSTOMER = 100;
const MAX_IMPORT_BYTES = 768 * 1024;
const MAX_IMPORT_DEPTH = 24;
const MAX_IMPORT_NODES = 10_000;
const MAX_IMPORT_ARRAY = 2_000;
const MAX_IMPORT_KEYS = 500;
const SENSITIVE_FIELD = /(?:pass(?:word|phrase)?|secret|token|credential|authorization|api[-_]?key|access[-_]?key|private[-_]?key|cookie|session)/i;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-\d+$/;
const CF_ACCOUNT = /^[0-9a-fA-F]{32}$/;
const AWS_ACCOUNT = /^\d{12}$/;
const RENDER_OWNER = /^(?:tea|usr)-[a-z0-9]+$/i;
const GENERIC_SCOPE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = Record<string, JsonValue>;

type CustomerApiDependencies = {
  repository: CustomerRepository;
  authDependencies?: CustomerAuthDependencies;
};

function responseNoStore(res: Response): Response {
  return res.set("Cache-Control", "no-store");
}

function genericError(res: Response, status: number) {
  return responseNoStore(res).status(status).json({ error: "generic" });
}

function objectBody(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function validLabel(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value);
}

function isProfileProvider(value: unknown): value is CustomerProfileProvider {
  return typeof value === "string" && (PROFILE_PROVIDERS as readonly string[]).includes(value);
}

function isImportProvider(value: unknown): value is CustomerScanProvider {
  return typeof value === "string" && (IMPORT_PROVIDERS as readonly string[]).includes(value);
}

function validScope(provider: CustomerProfileProvider, value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (provider === "cloudflare") return CF_ACCOUNT.test(value);
  if (provider === "aws") return AWS_ACCOUNT.test(value);
  if (provider === "render") return RENDER_OWNER.test(value);
  return GENERIC_SCOPE.test(value);
}

function validRegion(provider: CustomerProfileProvider, value: unknown): string | null | false {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > 64 || /[\u0000-\u001f\u007f]/.test(value)) return false;
  return provider === "aws" && !AWS_REGION.test(value) ? false : value;
}

function parseProfileBody(body: unknown): { provider: CustomerProfileProvider; label: string; scopeId: string; region: string | null } | null {
  const value = objectBody(body);
  if (!value) return null;
  const keys = Object.keys(value);
  if (keys.some(key => SENSITIVE_FIELD.test(key)) || keys.some(key => !["provider", "label", "scopeId", "region"].includes(key))) return null;
  if (!isProfileProvider(value.provider) || !validLabel(value.label) || !validScope(value.provider, value.scopeId)) return null;
  if (containsCredentialLikeValue(value.label, true) || containsCredentialLikeValue(value.scopeId) || containsCredentialLikeValue(value.region, true)) return null;
  const region = validRegion(value.provider, value.region);
  return region === false ? null : { provider: value.provider, label: value.label, scopeId: value.scopeId, region };
}

function recordId(req: Request): number | null {
  const value = Number(req.params.id);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function profileResponse(profile: { id: number; provider: CustomerProfileProvider; label: string; scopeId: string; region: string | null; createdAt: Date }) {
  return {
    id: profile.id,
    provider: profile.provider,
    label: profile.label,
    scopeId: profile.scopeId,
    region: profile.region,
    status: "manual_profile" as const,
    createdAt: profile.createdAt.toISOString(),
  };
}

function scanListResponse(scan: CustomerScanRecord) {
  return {
    id: scan.id,
    provider: scan.provider,
    status: scan.status,
    createdAt: scan.createdAt.toISOString(),
    connectionLabel: scan.connectionLabel,
    summaryAvailable: Boolean(scan.summaryCiphertext),
  };
}

function strictUtc(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
}

function boundedJson(value: unknown, depth = 0, counter = { nodes: 0 }): value is JsonValue {
  if (depth > MAX_IMPORT_DEPTH || ++counter.nodes > MAX_IMPORT_NODES) return false;
  if (value === null || typeof value === "boolean" || typeof value === "number") return Number.isFinite(value as number) || typeof value !== "number";
  if (typeof value === "string") return Buffer.byteLength(value, "utf8") <= 64 * 1024;
  if (Array.isArray(value)) return value.length <= MAX_IMPORT_ARRAY && value.every(entry => boundedJson(entry, depth + 1, counter));
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length <= MAX_IMPORT_KEYS && keys.every(key => key.length <= 256 && boundedJson(record[key], depth + 1, counter));
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key]!)}`);
  return `{${entries.join(",")}}`;
}

function redactImportedValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(redactImportedValue);
  if (!value || typeof value !== "object") return value;
  const safe: JsonRecord = Object.create(null) as JsonRecord;
  for (const [key, child] of Object.entries(value)) {
    safe[key] = SENSITIVE_FIELD.test(key) ? "[redacted]" : redactImportedValue(child);
  }
  return safe;
}

function stringArray(value: JsonValue | undefined, maximum = 50): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && entry.length <= 160).slice(0, maximum)
    : [];
}

function findCategories(report: JsonRecord): string[] {
  const findings = report.findings;
  if (!Array.isArray(findings)) return [];
  const allowed = new Set(["access_configuration", "authentication", "cloud_account_activity", "cloud_api_activity", "deployment", "deployment_configuration", "dns_configuration", "environment_configuration", "iam_configuration", "logging_configuration", "membership", "project_visibility", "railway_workspace_activity", "render_workspace_activity", "secret_access", "security_configuration", "shell_access", "token_management", "workspace_permissions", "persistence_indicator", "reverse_shell_indicator", "typosquatting_indicator"]);
  const categories = findings
    .map(finding => finding && typeof finding === "object" && !Array.isArray(finding) ? (finding as JsonRecord).category : undefined)
    .filter((value): value is string => typeof value === "string" && allowed.has(value));
  return [...new Set(categories)].slice(0, 100);
}

function importedReport(value: unknown, requestedProvider: unknown): { provider: CustomerScanProvider; report: JsonRecord } | null {
  const source = objectBody(value);
  if (!source || !boundedJson(source) || Array.isArray(source)) return null;
  const original = source as JsonRecord;
  let canonicalOriginal: string;
  try {
    canonicalOriginal = canonicalJson(original);
  } catch {
    return null;
  }
  if (Buffer.byteLength(canonicalOriginal, "utf8") > MAX_IMPORT_BYTES) return null;

  const embeddedProvider = original.provider;
  const provider = isImportProvider(requestedProvider) ? requestedProvider : isImportProvider(embeddedProvider) ? embeddedProvider : null;
  if (!provider || (isImportProvider(requestedProvider) && isImportProvider(embeddedProvider) && requestedProvider !== embeddedProvider)) return null;

  const sanitized = redactImportedValue(original) as JsonRecord;
  delete sanitized.summary;
  const canonicalSanitized = canonicalJson(sanitized);
  const suppliedScope = typeof sanitized.scopeId === "string" ? sanitized.scopeId : typeof sanitized.scope_id === "string" ? sanitized.scope_id : null;
  const suppliedSince = strictUtc(sanitized.since) ? sanitized.since : null;
  const suppliedUntil = strictUtc(sanitized.until) ? sanitized.until : null;

  return {
    provider,
    report: {
      report_format: "manual_customer_json_import_v1",
      provider,
      source_context: {
        source_kind: "customer_json_import_unverified",
        source_claim: provider === "local"
          ? "User-copied local operating-system or network-tool output; the portal did not verify the actual operating system, host, tool, identity, scope, or collection authority."
          : "User-copied provider or export output; the portal did not connect to, scan, enumerate, or verify the selected account, identity, scope, or collection authority.",
        canonical_original_sha256: sha256(canonicalOriginal),
        sanitized_representation_sha256: sha256(canonicalSanitized),
        original_representation_retained: false,
        supplied_scope: suppliedScope,
        supplied_since_utc: suppliedSince,
        supplied_until_utc: suppliedUntil,
      },
      sanitized_representation: sanitized,
      limitation_notice: "This is an unverified customer-provided import. It is not evidence of portal collection, verified identity, authorized access, complete coverage, compromise, or an all-clear result. Keep original evidence outside this portal.",
    },
  };
}

async function authenticated(req: Request, res: Response, dependencies: CustomerApiDependencies): Promise<ActiveCustomerSession | null> {
  try {
    const auth = dependencies.authDependencies ?? { repository: dependencies.repository };
    const active = await getAuthenticatedCustomerSession(req, res, auth);
    if (!active) genericError(res, 401);
    return active;
  } catch {
    genericError(res, 503);
    return null;
  }
}

async function mutationAuthenticated(req: Request, res: Response, dependencies: CustomerApiDependencies): Promise<ActiveCustomerSession | null> {
  const active = await authenticated(req, res, dependencies);
  if (!active) return null;
  const csrfToken = req.get("x-csrf-token");
  if (
    !csrfToken ||
    csrfToken.length > 512 ||
    !hasExpectedExternalOrigin(req, active.session.origin) ||
    !timingSafeTextEqual(sha256(csrfToken), active.session.csrfTokenHash)
  ) {
    genericError(res, 403);
    return null;
  }
  return active;
}

function createExplicitSummary(report: JsonRecord): JsonRecord {
  const source = objectBody(report.source_context) as JsonRecord | null;
  const sanitized = objectBody(report.sanitized_representation) as JsonRecord | null;
  // Parent-owned helper is intentionally only used after fresh explicit consent.
  const networkReview = reviewNetworkBoundaries(sanitized ?? {});
  const textIndicators = selectedTextIndicators(sanitized ?? {});
  const declaredSynthetic = sanitized?.synthetic === true || sanitized?.is_synthetic === true || sanitized?.simulation === true;
  const categories = sanitized ? findCategories(sanitized) : [];
  return {
    method: "consent_generated_local_summary",
    generated_utc: new Date().toISOString(),
    consent_purpose: "local summary",
    generated_only_after_fresh_explicit_consent: true,
    claim_status: "unknown_or_customer_declared_synthetic",
    observed_tooling_and_decoy_actions: {
      status: declaredSynthetic ? "report_declared_synthetic" : textIndicators.length ? "unverified_customer_supplied_text_indicators" : "unknown",
      report_declared_synthetic: declaredSynthetic,
      selected_indicators: textIndicators,
      uncertainty: "Imported labels are unverified text patterns, not execution, competence, identity or real access. No portal observation, host access, cloud access or decoy action occurred."
    },
    defensive_review_indicators: {
      categories,
      network_boundary_review: networkReview,
      source_claims: ["customer-provided sanitized JSON", "not independently verified"],
      uncertainty: "Categories and boundary indicators are limited to the sanitized user import and may be incomplete, synthetic, mistaken, or unrelated to a security event."
    },
    legally_relevant_context: {
      canonical_source_digest: typeof source?.canonical_original_sha256 === "string" ? source.canonical_original_sha256 : null,
      supplied_scope: typeof source?.supplied_scope === "string" ? source.supplied_scope : null,
      supplied_time_window: {
        since_utc: typeof source?.supplied_since_utc === "string" ? source.supplied_since_utc : null,
        until_utc: typeof source?.supplied_until_utc === "string" ? source.supplied_until_utc : null,
      },
      identity_not_verified: true,
      authorization_not_verified: true,
      unauthorized_access_not_established: true,
      not_legal_proof: true,
    },
    limitations: "This local summary does not replay raw payloads or removed secret fields. It is not a forensic finding, attribution, legal conclusion, authorization record, or proof of unauthorized access."
  };
}

export function registerCustomerApiRoutes(app: Express, dependencies: CustomerApiDependencies) {
  const listProfiles = async (req: Request, res: Response) => {
    const active = await authenticated(req, res, dependencies);
    if (!active) return;
    try {
      const profiles = await dependencies.repository.listProfiles(active.session.user.id);
      responseNoStore(res).json({ connections: profiles.map(profileResponse), profiles: profiles.map(profileResponse) });
    } catch {
      genericError(res, 503);
    }
  };

  const createProfile = async (req: Request, res: Response) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    if (!active) return;
    const profile = parseProfileBody(req.body);
    if (!profile) {
      genericError(res, 400);
      return;
    }
    try {
      if (await dependencies.repository.countProfiles(active.session.user.id) >= MAX_PROFILES_PER_CUSTOMER) {
        genericError(res, 429);
        return;
      }
      const saved = await dependencies.repository.createProfile({
        ownerId: active.session.user.id,
        ...profile,
        // This preserved ciphertext column is only an encrypted marker, never a cloud connection or secret.
        profileMarkerCiphertext: encryptPrivateJson({ mode: "metadata_only" }),
      });
      responseNoStore(res).status(201).json(profileResponse(saved));
    } catch {
      genericError(res, 503);
    }
  };

  const deleteProfile = async (req: Request, res: Response) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    const id = recordId(req);
    if (!active) return;
    if (!id) {
      genericError(res, 400);
      return;
    }
    try {
      const deleted = await dependencies.repository.deleteOwnedProfile(active.session.user.id, id);
      if (!deleted) {
        genericError(res, 404);
        return;
      }
      responseNoStore(res).json({ success: true });
    } catch {
      genericError(res, 503);
    }
  };

  app.post("/api/auth/logout", async (req, res) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    if (!active) return;
    try {
      await dependencies.repository.revokeSession(sha256(active.token));
      clearCustomerSessionCookies(res);
      responseNoStore(res).json({ success: true });
    } catch {
      genericError(res, 503);
    }
  });

  app.post("/api/auth/revoke-all", async (req, res) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    if (!active) return;
    try {
      await dependencies.repository.revokeAllSessions(active.session.user.id);
      clearCustomerSessionCookies(res);
      responseNoStore(res).json({ success: true });
    } catch {
      genericError(res, 503);
    }
  });

  app.get("/api/connections", listProfiles);
  app.post("/api/connections", createProfile);
  app.delete("/api/connections/:id", deleteProfile);
  // Metadata profile aliases for the updated frontend; legacy REST shapes remain available above.
  app.get("/api/profiles", listProfiles);
  app.post("/api/profiles", createProfile);
  app.delete("/api/profiles/:id", deleteProfile);

  app.get("/api/scans", async (req, res) => {
    const active = await authenticated(req, res, dependencies);
    if (!active) return;
    try {
      const scans = await dependencies.repository.listScans(active.session.user.id);
      responseNoStore(res).json({ scans: scans.map(scanListResponse) });
    } catch {
      genericError(res, 503);
    }
  });

  // Deliberately retained only as an explicit rejection for obsolete cloud execution clients.
  app.post("/api/scans", (_req, res) => {
    responseNoStore(res).status(410).json({ error: "manual_import_required" });
  });

  app.post("/api/scans/import", async (req, res) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    if (!active) return;
    const body = objectBody(req.body);
    const imported = body?.consent === true ? importedReport(body.report, body.provider) : null;
    if (!imported) {
      genericError(res, 400);
      return;
    }
    try {
      if (await dependencies.repository.countScans(active.session.user.id) >= MAX_IMPORTS_PER_CUSTOMER) {
        genericError(res, 429);
        return;
      }
      const scan = await dependencies.repository.createScan({
        ownerId: active.session.user.id,
        connectionId: null,
        provider: imported.provider,
        status: "completed",
        connectionLabel: null,
        reportCiphertext: encryptPrivateJson(imported.report),
      });
      responseNoStore(res).status(201).json({ scanId: scan.id, report: imported.report, summaryOffered: true });
    } catch {
      genericError(res, 503);
    }
  });

  app.get("/api/scans/:id", async (req, res) => {
    const active = await authenticated(req, res, dependencies);
    const id = recordId(req);
    if (!active) return;
    if (!id) {
      genericError(res, 400);
      return;
    }
    try {
      const scan = await dependencies.repository.findOwnedScan(active.session.user.id, id);
      if (!scan) {
        genericError(res, 404);
        return;
      }
      const report = decryptPrivateJson<JsonRecord>(scan.reportCiphertext);
      // Summaries are never auto-returned: every generation needs a new consented POST.
      responseNoStore(res).json({ scanId: scan.id, report, summaryOffered: true });
    } catch {
      genericError(res, 503);
    }
  });

  app.post("/api/scans/:id/summary", async (req, res) => {
    const active = await mutationAuthenticated(req, res, dependencies);
    const id = recordId(req);
    const body = objectBody(req.body);
    if (!active) return;
    if (!id || body?.consent !== true) {
      genericError(res, 400);
      return;
    }
    try {
      const scan = await dependencies.repository.findOwnedScan(active.session.user.id, id);
      if (!scan) {
        genericError(res, 404);
        return;
      }
      const report = decryptPrivateJson<JsonRecord>(scan.reportCiphertext);
      const summary = createExplicitSummary(report);
      const saved = await dependencies.repository.saveOwnedSummary(active.session.user.id, id, encryptPrivateJson(summary));
      if (!saved) throw new Error("summary unavailable");
      responseNoStore(res).json({ summary });
    } catch {
      genericError(res, 503);
    }
  });
}
