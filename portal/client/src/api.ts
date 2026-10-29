export type ProviderId = "managed";
export type CloudProvider = "cloudflare" | "aws" | "render" | "railway";
export type ReportProvider = CloudProvider | "local";

export interface AuthProvider {
  id: ProviderId;
  name: "Managed sign-in";
  loginPath: "/api/auth/start/managed";
}

export interface SessionUser {
  id: number;
  name: string;
  email: string | null;
  provider: string;
}

export interface SessionResponse {
  user: SessionUser | null;
  csrfToken: string | null;
}

/** A customer bookmark and scope label, never an authenticated provider connection. */
export interface ProviderProfile {
  id: number;
  provider: CloudProvider;
  label: string;
  scopeId: string;
  region: string | null;
  status: "manual_profile";
  createdAt: string;
}

export interface ImportedReportRecord {
  id: number;
  provider: ReportProvider;
  status: string;
  createdAt: string;
  summaryAvailable: boolean;
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface ImportedReportDetail {
  scanId: number;
  report: JsonObject;
  summary?: JsonObject;
}

const genericFailure = new Error("REQUEST_FAILED");

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) throw genericFailure;
  try {
    return (await response.json()) as T;
  } catch {
    throw genericFailure;
  }
}

export async function getApi<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  return readJson<T>(response);
}

async function writeApi<T>(
  path: string,
  method: "POST" | "DELETE",
  csrfToken: string | null,
  body?: unknown,
): Promise<T> {
  if (!csrfToken) throw genericFailure;
  const response = await fetch(path, {
    method,
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return readJson<T>(response);
}

export function postApi<T>(path: string, csrfToken: string | null, body: unknown): Promise<T> {
  return writeApi<T>(path, "POST", csrfToken, body);
}

export function deleteApi<T>(path: string, csrfToken: string | null): Promise<T> {
  return writeApi<T>(path, "DELETE", csrfToken);
}

export const api = {
  providers: () => getApi<{ providers: AuthProvider[] }>("/api/auth/providers"),
  session: () => getApi<SessionResponse>("/api/auth/session"),
  logout: (csrfToken: string | null) => postApi<{ success: true }>("/api/auth/logout", csrfToken, {}),

  profiles: () => getApi<{ profiles: ProviderProfile[] }>("/api/profiles"),
  createProfile: (
    csrfToken: string | null,
    body: { provider: CloudProvider; label: string; scopeId: string; region?: string },
  ) => postApi<ProviderProfile>("/api/profiles", csrfToken, body),
  removeProfile: (csrfToken: string | null, profileId: number) =>
    deleteApi<{ success: true }>(`/api/profiles/${profileId}`, csrfToken),

  importedReports: () => getApi<{ scans: ImportedReportRecord[] }>("/api/scans"),
  importedReport: (reportId: number) => getApi<ImportedReportDetail>(`/api/scans/${reportId}`),
  importReport: (csrfToken: string | null, report: JsonObject, provider?: ReportProvider) =>
    postApi<ImportedReportDetail>("/api/scans/import", csrfToken, {
      report,
      ...(provider ? { provider } : {}),
      consent: true,
    }),
  createSummary: (csrfToken: string | null, reportId: number) =>
    postApi<{ summary?: JsonObject } | JsonObject>(`/api/scans/${reportId}/summary`, csrfToken, {
      consent: true,
    }),
};
