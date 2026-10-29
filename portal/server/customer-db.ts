import { and, eq, gt, isNull } from "drizzle-orm";
import {
  customerConnections,
  customerOauthStates,
  customerScans,
  customerSessions,
  users,
} from "../drizzle/schema";
import { getDb } from "./db";

export type CustomerProfileProvider = "cloudflare" | "aws" | "render" | "railway";
export type CustomerScanProvider = CustomerProfileProvider | "local";

export type CustomerUserRecord = {
  id: number;
  provider: string;
  name: string;
  email: string | null;
};

export type CustomerSessionRecord = {
  id: number;
  userId: number;
  origin: string;
  tokenHash: string;
  csrfTokenHash: string;
  csrfTokenCiphertext: string;
  expiresAt: Date;
  revokedAt: Date | null;
  user: CustomerUserRecord;
};

export type OAuthStateRecord = {
  id: number;
  provider: "managed";
  origin: string;
  nonceHash: string;
  verifierCiphertext: string;
  expiresAt: Date;
};

export type CustomerProfileRecord = {
  id: number;
  ownerId: number;
  provider: CustomerProfileProvider;
  label: string;
  scopeId: string;
  region: string | null;
  profileMarkerCiphertext: string;
  createdAt: Date;
};

export type CustomerScanRecord = {
  id: number;
  ownerId: number;
  connectionId: number | null;
  provider: CustomerScanProvider;
  status: "completed";
  connectionLabel: string | null;
  reportCiphertext: string;
  summaryCiphertext: string | null;
  createdAt: Date;
};

export interface CustomerRepository {
  upsertCustomerUser(input: {
    managedSubject: string;
    name: string;
    email: string | null;
    loginMethod: string;
  }): Promise<CustomerUserRecord>;
  createOAuthState(input: {
    stateHash: string;
    provider: "managed";
    origin: string;
    nonceHash: string;
    verifierCiphertext: string;
    expiresAt: Date;
  }): Promise<void>;
  consumeOAuthState(stateHash: string): Promise<OAuthStateRecord | null>;
  createSession(input: {
    userId: number;
    origin: string;
    tokenHash: string;
    csrfTokenHash: string;
    csrfTokenCiphertext: string;
    expiresAt: Date;
  }): Promise<void>;
  findActiveSession(tokenHash: string): Promise<CustomerSessionRecord | null>;
  revokeSession(tokenHash: string): Promise<void>;
  revokeAllSessions(userId: number): Promise<void>;
  createProfile(input: Omit<CustomerProfileRecord, "id" | "createdAt">): Promise<CustomerProfileRecord>;
  countProfiles(ownerId: number): Promise<number>;
  listProfiles(ownerId: number): Promise<CustomerProfileRecord[]>;
  findOwnedProfile(ownerId: number, id: number): Promise<CustomerProfileRecord | null>;
  deleteOwnedProfile(ownerId: number, id: number): Promise<boolean>;
  createScan(input: Omit<CustomerScanRecord, "id" | "createdAt" | "summaryCiphertext">): Promise<CustomerScanRecord>;
  countScans(ownerId: number): Promise<number>;
  listScans(ownerId: number): Promise<CustomerScanRecord[]>;
  findOwnedScan(ownerId: number, id: number): Promise<CustomerScanRecord | null>;
  saveOwnedSummary(ownerId: number, id: number, summaryCiphertext: string): Promise<boolean>;
}

async function databaseOrThrow() {
  const db = await getDb();
  if (!db) throw new Error("database unavailable");
  return db;
}

export class DrizzleCustomerRepository implements CustomerRepository {
  async upsertCustomerUser(input: {
    managedSubject: string;
    name: string;
    email: string | null;
    loginMethod: string;
  }): Promise<CustomerUserRecord> {
    const db = await databaseOrThrow();
    await db
      .insert(users)
      .values({
        openId: input.managedSubject,
        provider: "managed",
        name: input.name,
        email: input.email,
        loginMethod: input.loginMethod,
        lastSignedIn: new Date(),
      })
      .onDuplicateKeyUpdate({
        set: {
          provider: "managed",
          name: input.name,
          email: input.email,
          loginMethod: input.loginMethod,
          lastSignedIn: new Date(),
        },
      });

    const rows = await db
      .select({ id: users.id, name: users.name, email: users.email, loginMethod: users.loginMethod })
      .from(users)
      .where(and(eq(users.provider, "managed"), eq(users.openId, input.managedSubject)))
      .limit(1);
    const user = rows[0];
    if (!user) throw new Error("managed customer unavailable");
    return {
      id: user.id,
      provider: user.loginMethod || "managed",
      name: user.name ?? "",
      email: user.email ?? null,
    };
  }

  async createOAuthState(input: {
    stateHash: string;
    provider: "managed";
    origin: string;
    nonceHash: string;
    verifierCiphertext: string;
    expiresAt: Date;
  }): Promise<void> {
    const db = await databaseOrThrow();
    await db.insert(customerOauthStates).values({
      stateHash: input.stateHash,
      provider: input.provider,
      origin: input.origin,
      nonce: input.nonceHash,
      verifierCiphertext: input.verifierCiphertext,
      expiresAt: input.expiresAt,
    });
  }

  async consumeOAuthState(stateHash: string): Promise<OAuthStateRecord | null> {
    const db = await databaseOrThrow();
    const now = new Date();
    const rows = await db
      .select()
      .from(customerOauthStates)
      .where(and(eq(customerOauthStates.stateHash, stateHash), isNull(customerOauthStates.usedAt), gt(customerOauthStates.expiresAt, now)))
      .limit(1);
    const state = rows[0];
    if (!state || state.provider !== "managed") return null;
    const result = await db
      .update(customerOauthStates)
      .set({ usedAt: now })
      .where(and(eq(customerOauthStates.id, state.id), isNull(customerOauthStates.usedAt)));
    if (result[0].affectedRows !== 1) return null;
    return {
      id: state.id,
      provider: "managed",
      origin: state.origin,
      nonceHash: state.nonce,
      verifierCiphertext: state.verifierCiphertext,
      expiresAt: state.expiresAt,
    };
  }

  async createSession(input: {
    userId: number;
    origin: string;
    tokenHash: string;
    csrfTokenHash: string;
    csrfTokenCiphertext: string;
    expiresAt: Date;
  }): Promise<void> {
    const db = await databaseOrThrow();
    await db.insert(customerSessions).values(input);
  }

  async findActiveSession(tokenHash: string): Promise<CustomerSessionRecord | null> {
    const db = await databaseOrThrow();
    const rows = await db
      .select({
        session: customerSessions,
        user: { id: users.id, name: users.name, email: users.email, loginMethod: users.loginMethod, provider: users.provider },
      })
      .from(customerSessions)
      .innerJoin(users, eq(customerSessions.userId, users.id))
      .where(and(eq(customerSessions.tokenHash, tokenHash), isNull(customerSessions.revokedAt), gt(customerSessions.expiresAt, new Date())))
      .limit(1);
    const row = rows[0];
    if (!row || row.user.provider !== "managed") return null;
    return {
      id: row.session.id,
      userId: row.session.userId,
      origin: row.session.origin,
      tokenHash: row.session.tokenHash,
      csrfTokenHash: row.session.csrfTokenHash,
      csrfTokenCiphertext: row.session.csrfTokenCiphertext,
      expiresAt: row.session.expiresAt,
      revokedAt: row.session.revokedAt,
      user: {
        id: row.user.id,
        provider: row.user.loginMethod || "managed",
        name: row.user.name ?? "",
        email: row.user.email ?? null,
      },
    };
  }

  async revokeSession(tokenHash: string): Promise<void> {
    const db = await databaseOrThrow();
    await db.update(customerSessions).set({ revokedAt: new Date() }).where(and(eq(customerSessions.tokenHash, tokenHash), isNull(customerSessions.revokedAt)));
  }

  async revokeAllSessions(userId: number): Promise<void> {
    const db = await databaseOrThrow();
    await db.update(customerSessions).set({ revokedAt: new Date() }).where(and(eq(customerSessions.userId, userId), isNull(customerSessions.revokedAt)));
  }

  async createProfile(input: Omit<CustomerProfileRecord, "id" | "createdAt">): Promise<CustomerProfileRecord> {
    const db = await databaseOrThrow();
    const result = await db.insert(customerConnections).values(input).$returningId();
    const id = result[0]?.id;
    if (typeof id !== "number") throw new Error("profile write failed");
    const profile = await this.findOwnedProfile(input.ownerId, id);
    if (!profile) throw new Error("profile unavailable");
    return profile;
  }

  async countProfiles(ownerId: number): Promise<number> {
    return (await this.listProfiles(ownerId)).length;
  }

  async listProfiles(ownerId: number): Promise<CustomerProfileRecord[]> {
    const db = await databaseOrThrow();
    const rows = await db.select().from(customerConnections).where(eq(customerConnections.ownerId, ownerId)).orderBy(customerConnections.createdAt);
    return rows as CustomerProfileRecord[];
  }

  async findOwnedProfile(ownerId: number, id: number): Promise<CustomerProfileRecord | null> {
    const db = await databaseOrThrow();
    const rows = await db.select().from(customerConnections).where(and(eq(customerConnections.id, id), eq(customerConnections.ownerId, ownerId))).limit(1);
    return (rows[0] as CustomerProfileRecord | undefined) ?? null;
  }

  async deleteOwnedProfile(ownerId: number, id: number): Promise<boolean> {
    const db = await databaseOrThrow();
    const result = await db.delete(customerConnections).where(and(eq(customerConnections.id, id), eq(customerConnections.ownerId, ownerId)));
    return result[0].affectedRows === 1;
  }

  async createScan(input: Omit<CustomerScanRecord, "id" | "createdAt" | "summaryCiphertext">): Promise<CustomerScanRecord> {
    const db = await databaseOrThrow();
    const result = await db.insert(customerScans).values({ ...input, summaryCiphertext: null }).$returningId();
    const id = result[0]?.id;
    if (typeof id !== "number") throw new Error("import write failed");
    const scan = await this.findOwnedScan(input.ownerId, id);
    if (!scan) throw new Error("import unavailable");
    return scan;
  }

  async countScans(ownerId: number): Promise<number> {
    return (await this.listScans(ownerId)).length;
  }

  async listScans(ownerId: number): Promise<CustomerScanRecord[]> {
    const db = await databaseOrThrow();
    const rows = await db.select().from(customerScans).where(eq(customerScans.ownerId, ownerId)).orderBy(customerScans.createdAt);
    return rows as CustomerScanRecord[];
  }

  async findOwnedScan(ownerId: number, id: number): Promise<CustomerScanRecord | null> {
    const db = await databaseOrThrow();
    const rows = await db.select().from(customerScans).where(and(eq(customerScans.id, id), eq(customerScans.ownerId, ownerId))).limit(1);
    return (rows[0] as CustomerScanRecord | undefined) ?? null;
  }

  async saveOwnedSummary(ownerId: number, id: number, summaryCiphertext: string): Promise<boolean> {
    const db = await databaseOrThrow();
    const result = await db.update(customerScans).set({ summaryCiphertext }).where(and(eq(customerScans.id, id), eq(customerScans.ownerId, ownerId)));
    return result[0].affectedRows === 1;
  }
}
