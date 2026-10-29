/** Conservative metadata guard. It is not a guarantee that arbitrary secrets can be recognized. */
export function containsCredentialLikeValue(value: unknown, freeText = false): boolean {
  if (typeof value !== "string") return false;
  if (/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(value)) return true;
  if (/\b(?:gh[pousr]_|github_pat_|rnd_|rwy_|railway_|cloudflare_)[A-Za-z0-9_-]{10,}\b/.test(value)) return true;
  if (/\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(value)) return true;
  if (/(?:password|passwd|secret|token|api[-_]?key|credential)\s*[:=]\s*\S+/i.test(value)) return true;
  if (/https?:\/\/[^/\s]*:[^@/\s]+@/i.test(value)) return true;
  // Human labels and regions need no long, opaque unbroken credential-like value.
  return freeText && value.length >= 32 && /^[A-Za-z0-9+/_=]+$/.test(value);
}
