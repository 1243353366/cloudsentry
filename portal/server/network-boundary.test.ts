import { describe, expect, it } from "vitest";
import { reviewNetworkBoundaries } from "./network-boundary";

describe("offline network-boundary review", () => {
  it("reports unassessed coverage without configuration", () => {
    const result = reviewNetworkBoundaries({ provider: "local" });
    expect(result.status).toBe("not_assessed_no_configuration_supplied");
    expect(result.not_assessed).toContain("DHCP server authorization");
    expect(result.boundary_notice).toContain("No network probe");
  });
  it("detects supplied overlap without calling it an intrusion", () => {
    const result = reviewNetworkBoundaries({ networks: ["192.0.2.0/24", "192.0.2.128/25", "198.51.100.0/24"] });
    expect(result.indicators.filter(item => item.code === "overlapping_network_definitions")).toHaveLength(1);
    expect(result.indicators.every(item => item.assessment === "review_only")).toBe(true);
    expect(result.provenance).toContain("Unverified");
  });
  it("handles IPv6 and keeps IPv4 families separate", () => {
    const result = reviewNetworkBoundaries({ networks: ["2001:db8::/32", "2001:db8:1::/48", "192.0.2.0/24"] });
    expect(result.indicators.filter(item => item.code === "overlapping_network_definitions")).toHaveLength(1);
    expect(result.reference_policy.interpretation).toContain("not access-control");
  });
  it("distinguishes host-bit definitions and malformed prefixes", () => {
    const result = reviewNetworkBoundaries({ networks: ["192.0.2.7/24", "192.0.2.0/33", "not-a-cidr"] });
    expect(result.indicators.some(item => item.code === "network_definition_has_host_bits")).toBe(true);
    expect(result.indicators.filter(item => item.code === "invalid_or_unsupported_cidr")).toHaveLength(2);
  });
  it("bounds quadratic work and does not copy arbitrary input text", () => {
    const result = reviewNetworkBoundaries({ networks: Array(300).fill("192.0.2.0/24"), password: "PRIVATE-MARKER" });
    expect(result.coverage.networks_reviewed).toBe(128);
    expect(result.coverage.input_truncated).toBe(true);
    expect(result.indicators.length).toBe(256);
    expect(result.coverage.indicators_truncated).toBe(true);
    expect(JSON.stringify(result)).not.toContain("PRIVATE-MARKER");
  });
  it("reviews route families as configuration only", () => {
    const result = reviewNetworkBoundaries({ networks: [], routes: [{ destination: "192.0.2.0/24", gateway: "2001:db8::1" }] });
    expect(result.indicators[0]?.code).toBe("route_gateway_family_review");
  });
});
