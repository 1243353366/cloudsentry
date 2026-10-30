export type IntegrationState = "core_only" | "customer_authorized_integration" | "integration_unavailable" | "credential_expired_or_revoked";
export type IntegrationTrust = {
  state: IntegrationState;
  label: string;
  detail: string;
  checkedAtUtc: string | null;
  verifiedByPortal: false;
  evidenceDigest: string | null;
};

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function utc(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 40 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== value.slice(0, 19) ? null : date.toISOString();
}

/** Presentation only: no provider call, permission decision or verification. */
function classifyDeclaration(report?: unknown): Omit<IntegrationTrust, "evidenceDigest"> {
  if (report === undefined) return {
    state: "core_only", label: "Core-only mode", checkedAtUtc: null, verifiedByPortal: false,
    detail: "No cloud-provider keys are used by this portal. Manual imports and local analysis remain available; managed sign-in is separate from provider authorization.",
  };
  const root = object(report);
  const supplied = object(root?.sanitized_representation) ?? root;
  const status = object(supplied?.integration_status);
  const unavailable: Omit<IntegrationTrust, "evidenceDigest"> = {
    state: "integration_unavailable", label: "Integration unavailable / not verified here", checkedAtUtc: null, verifiedByPortal: false,
    detail: "No supported local-collection status was supplied. Profiles and imported reports do not establish provider access. Selected content can still be reviewed; cloud visibility and credential validity are unknown.",
  };
  if (!status || status.source !== "local_explicit_collection" || status.read_only_requests !== true) return unavailable;
  const checked = utc(status.checked_at_utc);
  if (!checked) return unavailable;
  if (status.state === "customer_authorized_integration") return {
    state: "customer_authorized_integration", label: "Reported customer-authorized integration", checkedAtUtc: checked, verifiedByPortal: false,
    detail: "The supplied local collector reports a read-only response at the stated time. This import is unverified; it is not ongoing access, authorization proof, a portal connection or complete cloud coverage.",
  };
  if (status.state === "credential_expired_or_revoked") return {
    state: "credential_expired_or_revoked", label: "Reported credential expired/revoked", checkedAtUtc: checked, verifiedByPortal: false,
    detail: "The supplied local collector reports an explicit credential failure. This declaration is unverified here; it does not establish a revocation cause or current status. Review provider access natively and rerun locally only if you choose.",
  };
  if (status.state === "integration_unavailable") return {
    ...unavailable, label: "Reported integration unavailable", checkedAtUtc: checked,
    detail: "The supplied local collector reports unavailable access. Network, service, configuration or permission issues may be involved; do not infer expiry or revocation from missing visibility. No fallback scan or shared credential is used.",
  };
  return unavailable;
}

export function describeIntegrationTrust(report?: unknown): IntegrationTrust {
  const context = object(object(report)?.source_context);
  const digest = context?.sanitized_representation_sha256;
  return {
    ...classifyDeclaration(report),
    evidenceDigest: typeof digest === "string" && /^[a-f0-9]{64}$/.test(digest) ? digest : null,
  };
}
