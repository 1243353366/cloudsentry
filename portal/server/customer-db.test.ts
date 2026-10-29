import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const repositorySource = readFileSync(new URL("./customer-db.ts", import.meta.url), "utf8");

describe("customer repository ownership predicates", () => {
  it("keeps owner identifiers in connection and scan select/delete/update predicates", () => {
    expect(repositorySource).toContain(
      "where(and(eq(customerConnections.id, id), eq(customerConnections.ownerId, ownerId)))"
    );
    expect(repositorySource).toContain(
      "where(and(eq(customerScans.id, id), eq(customerScans.ownerId, ownerId)))"
    );
    expect(repositorySource).toContain(
      "where(and(eq(customerConnections.id, id), eq(customerConnections.ownerId, ownerId)))"
    );
    expect(repositorySource).toContain(
      "where(and(eq(customerScans.id, id), eq(customerScans.ownerId, ownerId)))"
    );
  });
});
