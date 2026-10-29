/**
 * Browser-facing origins are intentionally code-owned. Do not derive an origin
 * from Host, forwarded headers, query data, or an environment variable.
 *
 * The production literal remains null until the publisher has a verified final
 * deployment URL. This makes production managed login fail closed on the first
 * publication instead of accepting an untrusted callback origin.
 */
export const PRODUCTION_ORIGIN: string | null = "https://csportal-brpeckhv.manus.space";
export const PREVIEW_ORIGIN = "https://8328-i0x67khfjej84ssai8t22-79cba3e2.us5.manus.computer";

export const trustedOrigins: readonly string[] = Object.freeze([
  PREVIEW_ORIGIN,
  ...(PRODUCTION_ORIGIN ? [PRODUCTION_ORIGIN] : []),
]);

export function isTrustedOrigin(origin: string): boolean {
  return trustedOrigins.includes(origin);
}
