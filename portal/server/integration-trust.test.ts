import { describe, expect, it } from "vitest";
import { describeIntegrationTrust } from "../client/src/integration-trust";

const declaration = (state: string) => ({ integration_status: { state, source: "local_explicit_collection", read_only_requests: true, checked_at_utc: "2026-10-30T00:00:00Z" } });

describe("independent integration trust presentation", () => {
  it("keeps the baseline keyless rather than inventing cloud connectivity", () => {
    expect(describeIntegrationTrust().state).toBe("core_only");
    expect(describeIntegrationTrust().verifiedByPortal).toBe(false);
  });
  it("does not treat a profile, native export or arbitrary state as provider authorization", () => {
    for (const value of [null, [], {}, { status: "connected" }, { provider: "aws", scopeId: "123456789012" }, declaration("connected")]) {
      expect(describeIntegrationTrust(value).state).toBe("integration_unavailable");
    }
  });
  it("shows every supported collector declaration without upgrading its provenance", () => {
    for (const state of ["customer_authorized_integration", "integration_unavailable", "credential_expired_or_revoked"] as const) {
      const result = describeIntegrationTrust({ sanitized_representation: declaration(state) });
      expect(result.state).toBe(state);
      expect(result.verifiedByPortal).toBe(false);
      expect(result.checkedAtUtc).toBe("2026-10-30T00:00:00.000Z");
    }
  });
  it("rejects unsafe or incomplete claims without echoing payloads", () => {
    const report = declaration("customer_authorized_integration");
    Object.assign(report.integration_status, { source: "<script>credential-secret</script>", checked_at_utc: "2026-02-31T00:00:00Z", read_only_requests: true });
    const result = describeIntegrationTrust(report);
    expect(result.state).toBe("integration_unavailable");
    expect(JSON.stringify(result)).not.toContain("credential-secret");
  });
  it("requires a valid supplied timestamp and literal read-only declaration", () => {
    for (const changed of [{ checked_at_utc: "unknown" }, { checked_at_utc: "2026-02-31T00:00:00Z" }, { read_only_requests: "true" }, { checked_at_utc: "2026-10-30T00:00:00+00:00" }]) {
      const report = declaration("customer_authorized_integration");
      Object.assign(report.integration_status, changed);
      expect(describeIntegrationTrust(report).state).toBe("integration_unavailable");
    }
  });
  it("retains the bounded representation reference without upgrading its authenticity", () => {
    const report = { sanitized_representation: declaration("customer_authorized_integration"), source_context: { sanitized_representation_sha256: "a".repeat(64), unwanted: "do-not-copy" } };
    const result = describeIntegrationTrust(report);
    expect(result.evidenceDigest).toBe("a".repeat(64));
    expect(result.verifiedByPortal).toBe(false);
    expect(JSON.stringify(result)).not.toContain("do-not-copy");
    report.source_context.sanitized_representation_sha256 = "unsafe";
    expect(describeIntegrationTrust(report).evidenceDigest).toBe(null);
  });
});
