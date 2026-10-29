export const CUSTOMER_AUTH_PROVIDERS = ["google", "github", "microsoft"] as const;
export type CustomerAuthProvider = (typeof CUSTOMER_AUTH_PROVIDERS)[number];

export const CUSTOMER_CLOUD_PROVIDERS = [
  "cloudflare",
  "aws",
  "render",
  "railway",
] as const;
export type CustomerCloudProvider = (typeof CUSTOMER_CLOUD_PROVIDERS)[number];

export type CustomerSessionResponse = {
  user: {
    id: number;
    name: string;
    email: string | null;
    provider: CustomerAuthProvider;
  } | null;
  csrfToken: string | null;
};

export type CustomerConnectionResponse = {
  id: number;
  provider: CustomerCloudProvider;
  label: string;
  scopeId: string;
  region: string | null;
  status: "configured";
  createdAt: string;
};

export type CustomerScanListItem = {
  id: number;
  provider: CustomerCloudProvider;
  status: "completed";
  createdAt: string;
  connectionLabel: string | null;
  summaryAvailable: boolean;
};
