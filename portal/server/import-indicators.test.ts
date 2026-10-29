import { describe, expect, it } from "vitest";
import { selectedTextIndicators } from "./import-indicators";

describe("selected imported text indicators", () => {
  it("retains fixed labels as unverified patterns, not capability", () => {
    const result = selectedTextIndicators({ events: [{ language_indicator: "php", token_indicators: ["network_api", "process_api"], simulation: true, command_sha256: "0".repeat(64) }] });
    expect(result).toHaveLength(1);
    expect(result[0]?.report_declared_simulation).toBe(true);
    expect(result[0]?.interpretation).toContain("not execution");
  });
  it("does not replay raw command text or arbitrary label strings", () => {
    const result = selectedTextIndicators({ events: [{ language_indicator: "PRIVATE-MARKER", verb: "echo SECRET", token_indicators: ["PAYLOAD-MARKER"], command: "RAW-COMMAND" }] });
    expect(result).toEqual([]);
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE|PAYLOAD|RAW/);
  });
  it("bounds event work and uses source indexes instead of invented identities", () => {
    const result = selectedTextIndicators({ timeline: Array(300).fill({ verb: "php" }) });
    expect(result).toHaveLength(256);
    expect(result[0]?.source_index).toBe(0);
  });
});
