import {
  index,
  int,
  mediumtext,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  uniqueIndex,
  varchar,
} from "drizzle-orm/mysql-core";

/**
 * The starter user table remains compatible with existing rows. Keyless portal
 * identities use a stable managed-subject hash in openId, provider="managed",
 * and never link records by email.
 */
export const users = mysqlTable(
  "users",
  {
    id: int("id").autoincrement().primaryKey(),
    openId: varchar("openId", { length: 64 }).notNull().unique(),
    provider: varchar("provider", { length: 16 }),
    name: text("name"),
    email: varchar("email", { length: 320 }),
    loginMethod: varchar("loginMethod", { length: 64 }),
    role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
    lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
  },
  table => [index("users_provider_openId_idx").on(table.provider, table.openId)]
);

export const customerSessions = mysqlTable(
  "customer_sessions",
  {
    id: int("id").autoincrement().primaryKey(),
    userId: int("userId").notNull(),
    origin: varchar("origin", { length: 255 }).notNull(),
    tokenHash: varchar("tokenHash", { length: 64 }).notNull().unique(),
    csrfTokenHash: varchar("csrfTokenHash", { length: 64 }).notNull(),
    csrfTokenCiphertext: mediumtext("csrfTokenCiphertext").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    expiresAt: timestamp("expiresAt").notNull(),
    revokedAt: timestamp("revokedAt"),
  },
  table => [index("customer_sessions_user_expiry_idx").on(table.userId, table.expiresAt)]
);

export const customerOauthStates = mysqlTable(
  "customer_oauth_states",
  {
    id: int("id").autoincrement().primaryKey(),
    // Stores SHA-256(nonce), not the browser-visible encoded state value.
    stateHash: varchar("stateHash", { length: 64 }).notNull().unique(),
    provider: varchar("provider", { length: 16 }).notNull(),
    origin: varchar("origin", { length: 255 }).notNull(),
    nonce: varchar("nonce", { length: 128 }).notNull(),
    // Kept as an encrypted opaque managed-flow marker; no PKCE or client secret is stored.
    verifierCiphertext: mediumtext("verifierCiphertext").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    expiresAt: timestamp("expiresAt").notNull(),
    usedAt: timestamp("usedAt"),
  },
  table => [index("customer_oauth_states_expiry_idx").on(table.expiresAt)]
);

export const customerConnections = mysqlTable(
  "customer_connections",
  {
    id: int("id").autoincrement().primaryKey(),
    ownerId: int("ownerId").notNull(),
    provider: varchar("provider", { length: 16 }).notNull(),
    label: varchar("label", { length: 128 }).notNull(),
    scopeId: varchar("scopeId", { length: 128 }).notNull(),
    region: varchar("region", { length: 64 }),
    // Preserve the established DB cipher column while changing its meaning.
    profileMarkerCiphertext: mediumtext("credentialsCiphertext").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => [index("customer_connections_owner_idx").on(table.ownerId)]
);

export const customerScans = mysqlTable(
  "customer_scans",
  {
    id: int("id").autoincrement().primaryKey(),
    ownerId: int("ownerId").notNull(),
    connectionId: int("connectionId"),
    provider: varchar("provider", { length: 16 }).notNull(),
    status: varchar("status", { length: 16 }).notNull().default("completed"),
    connectionLabel: varchar("connectionLabel", { length: 128 }),
    reportCiphertext: mediumtext("reportCiphertext").notNull(),
    summaryCiphertext: mediumtext("summaryCiphertext"),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => [index("customer_scans_owner_created_idx").on(table.ownerId, table.createdAt)]
);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type CustomerSession = typeof customerSessions.$inferSelect;
export type CustomerConnection = typeof customerConnections.$inferSelect;
export type CustomerScan = typeof customerScans.$inferSelect;
