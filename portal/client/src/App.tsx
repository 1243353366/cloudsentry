import {
  type ChangeEvent,
  type FormEvent,
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link, Route, Switch, useLocation } from "wouter";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Download,
  FileJson2,
  FileUp,
  FolderOpen,
  LoaderCircle,
  LogOut,
  Menu,
  Network,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import {
  api,
  type AuthProvider,
  type CloudProvider,
  type ImportedReportDetail,
  type ImportedReportRecord,
  type JsonObject,
  type JsonValue,
  type ProviderProfile,
  type ReportProvider,
  type SessionResponse,
} from "./api";
import { GENERIC_REQUEST_ERROR, MAX_IMPORTED_REPORT_BYTES } from "./const";
import { describeIntegrationTrust } from "./integration-trust";

const REPORT_VIEW_LIMIT = 512 * 1024;
const SENSITIVE_KEY = /(?:access.?key|authorization|credential|cookie|pass(?:word|phrase)?|secret|session.?token|token|private.?key)/i;
const CLOUD_PROVIDERS: CloudProvider[] = ["cloudflare", "aws", "render", "railway"];
const REPORT_PROVIDERS: ReportProvider[] = [...CLOUD_PROVIDERS, "local"];

const PROVIDER_DASHBOARDS: Array<{ provider: CloudProvider; href: string; label: string; detail: string }> = [
  { provider: "cloudflare", href: "https://dash.cloudflare.com", label: "Cloudflare dashboard", detail: "Sign in and export only the account activity you choose." },
  { provider: "aws", href: "https://console.aws.amazon.com/cloudtrail/", label: "AWS CloudTrail", detail: "Use your native AWS access to select and export relevant events." },
  { provider: "render", href: "https://dashboard.render.com", label: "Render dashboard", detail: "Review your own workspace and prepare a selected export." },
  { provider: "railway", href: "https://railway.com/dashboard", label: "Railway dashboard", detail: "Use Railway’s own tools to select the result you want to import." },
];

type PortalContextValue = {
  session: SessionResponse | null;
  providers: AuthProvider[] | null;
  loading: boolean;
  unavailable: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<boolean>;
};

const PortalContext = createContext<PortalContextValue | null>(null);

function usePortal() {
  const context = useContext(PortalContext);
  if (!context) throw new Error("Portal context is unavailable");
  return context;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isReportProvider(value: unknown): value is ReportProvider {
  return typeof value === "string" && REPORT_PROVIDERS.includes(value as ReportProvider);
}

function filteredValue(value: unknown, depth = 0): JsonValue {
  if (depth > 8) return "[truncated: nesting limit]";
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    if (typeof value === "string" && value.length > 4096) return `${value.slice(0, 4096)}… [truncated]`;
    return value as string | number | boolean | null;
  }
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => filteredValue(entry, depth + 1));
  if (typeof value === "object") {
    const next: JsonObject = Object.create(null) as JsonObject;
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 100)) {
      next[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : filteredValue(child, depth + 1);
    }
    return next;
  }
  return "[unavailable value]";
}

function boundedReport(report: JsonObject): JsonObject {
  const filtered = filteredValue(report);
  const serialized = JSON.stringify(filtered);
  if (serialized.length <= REPORT_VIEW_LIMIT && isJsonObject(filtered)) return filtered;
  return {
    notice: "The selected report is too large to display or download in this portal view.",
    preview: serialized.slice(0, REPORT_VIEW_LIMIT),
  };
}

function jsonText(value: unknown): string {
  return JSON.stringify(filteredValue(value), null, 2);
}

function formatTime(value: string): string {
  const time = new Date(value);
  return Number.isNaN(time.valueOf())
    ? "Time unavailable"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(time);
}

function providerName(provider: ReportProvider): string {
  if (provider === "cloudflare") return "Cloudflare";
  if (provider === "aws") return "AWS";
  if (provider === "render") return "Render";
  if (provider === "railway") return "Railway";
  return "Local";
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/" className={`brand ${compact ? "brand--compact" : ""}`} aria-label="CloudSentry home">
      <span className="brand-mark" aria-hidden="true"><ShieldCheck size={compact ? 20 : 24} strokeWidth={2.15} /></span>
      <span className="brand-wordmark"><span>Cloud</span><strong>Sentry</strong></span>
    </Link>
  );
}

function IntegrationTrustNotice({ report }: { report?: JsonObject }) {
  const trust = describeIntegrationTrust(report);
  return <section className="integration-trust" aria-label="Integration trust and coverage">
    <div className="integration-trust__label"><ShieldCheck size={16} aria-hidden="true" /><strong>{trust.label}</strong>{report ? <span className="provider-pill">Unverified import</span> : null}</div>
    <p>{trust.detail}</p>
    {trust.checkedAtUtc ? <p className="fine-print">Supplied local check time: <span className="mono">{trust.checkedAtUtc}</span>. The portal does not poll or revalidate provider access.</p> : null}
    {trust.evidenceDigest ? <p className="fine-print">Imported sanitized representation SHA-256: <span className="mono">{trust.evidenceDigest}</span>. This is a processing reference, not source authentication.</p> : null}
  </section>;
}

function BusyLabel({ children }: { children: ReactNode }) {
  return <span className="button-content"><LoaderCircle className="spin" size={16} aria-hidden="true" />{children}</span>;
}

function ErrorMessage({ message = GENERIC_REQUEST_ERROR }: { message?: string }) {
  return <div className="inline-error" role="alert"><AlertTriangle size={17} aria-hidden="true" /><span>{message}</span></div>;
}

function ServiceState({ title, detail, retry }: { title: string; detail: string; retry?: () => void }) {
  return (
    <main className="public-state shell-width">
      <Brand />
      <div className="state-card" aria-live="polite">
        <LoaderCircle className="spin state-icon" size={24} aria-hidden="true" />
        <h1>{title}</h1>
        <p>{detail}</p>
        {retry ? <button className="button button--secondary" type="button" onClick={retry}><RefreshCw size={16} aria-hidden="true" />Retry</button> : null}
      </div>
    </main>
  );
}

function PortalProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [providers, setProviders] = useState<AuthProvider[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setUnavailable(false);
    try {
      const [providerResponse, sessionResponse] = await Promise.all([api.providers(), api.session()]);
      setProviders(providerResponse.providers);
      setSession(sessionResponse);
    } catch {
      setProviders(null);
      setSession(null);
      setUnavailable(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const logout = useCallback(async () => {
    const csrfToken = session?.csrfToken ?? null;
    if (!csrfToken) return false;
    try {
      await api.logout(csrfToken);
      setSession({ user: null, csrfToken: null });
      return true;
    } catch {
      return false;
    }
  }, [session?.csrfToken]);

  const value = useMemo(
    () => ({ session, providers, loading, unavailable, refresh, logout }),
    [session, providers, loading, unavailable, refresh, logout],
  );
  return <PortalContext.Provider value={value}>{children}</PortalContext.Provider>;
}

function validManagedProvider(providers: AuthProvider[]): AuthProvider | null {
  return providers.find((provider) => (
    provider.id === "managed" &&
    provider.name === "Managed sign-in" &&
    provider.loginPath === "/api/auth/start/managed"
  )) ?? null;
}

function LoginPanel() {
  const { providers, loading, unavailable, refresh, session } = usePortal();
  const [, navigate] = useLocation();

  if (session?.user) {
    return (
      <div className="sign-in-panel sign-in-panel--ready">
        <p className="eyebrow">Managed customer session</p>
        <h2>{session.user.name}</h2>
        <p>Your active managed session is ready for manual imports and provider-profile metadata.</p>
        <button className="button button--primary" type="button" onClick={() => navigate("/workspace")}>Open workspace<ChevronRight size={17} aria-hidden="true" /></button>
      </div>
    );
  }

  if (loading) {
    return <div className="sign-in-panel" aria-live="polite"><LoaderCircle className="spin" size={20} aria-hidden="true" /><p>Checking managed sign-in…</p></div>;
  }

  const managed = providers ? validManagedProvider(providers) : null;
  if (unavailable || !managed) {
    return (
      <div className="sign-in-panel">
        <ErrorMessage message="Managed sign-in is unavailable. No customer workspace is opened without a verified managed session." />
        <button className="button button--secondary" type="button" onClick={() => void refresh()}><RefreshCw size={16} aria-hidden="true" />Retry sign-in check</button>
      </div>
    );
  }

  const login = () => {
    const origin = encodeURIComponent(window.location.origin);
    window.location.assign(`${managed.loginPath}?origin=${origin}`);
  };

  return (
    <div className="sign-in-panel">
      <p className="eyebrow">Customer sign-in</p>
      <h2>Continue through the managed portal.</h2>
      <p className="sign-in-intro">Choose Google, Microsoft, or a passkey on the managed sign-in portal. CloudSentry does not show or operate a direct provider login.</p>
      <button className="button button--provider" type="button" onClick={login}><span>Managed sign-in</span><span className="provider-action">Continue</span></button>
    </div>
  );
}

function HomePage() {
  return (
    <main className="landing-page">
      <header className="landing-header shell-width"><Brand /><Link className="text-link" href="/privacy">Privacy statement<ArrowUpRight size={15} aria-hidden="true" /></Link></header>
      <section className="landing-hero shell-width" aria-labelledby="landing-title">
        <div className="hero-copy">
          <p className="eyebrow">Customer-operated evidence review</p>
          <h1 id="landing-title">Bring your export.<br /><em>Keep your control.</em></h1>
          <p className="hero-lede">CloudSentry is a calm room for customer-selected JSON evidence. Use managed sign-in, keep provider authorization in each provider’s own tools, and explicitly import only the results you choose.</p>
          <p><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/CHANGELOG.md" target="_blank" rel="noopener external">What changed: core 0.1.1 / portal 1.0.1, with the previous release archived<ArrowUpRight size={15} aria-hidden="true" /></a></p>
          <div className="hero-principles" aria-label="CloudSentry operating principles">
            <span><ShieldCheck size={16} aria-hidden="true" /> Managed customer session</span>
            <span><FolderOpen size={16} aria-hidden="true" /> Metadata-only profiles</span>
            <span><FileUp size={16} aria-hidden="true" /> Explicit JSON imports</span>
          </div>
          <IntegrationTrustNotice />
        </div>
        <div className="hero-login-wrap"><LoginPanel /></div>
      </section>
      <section className="security-strip shell-width" aria-label="How CloudSentry works">
        <div><span className="strip-number">01</span><h2>Use managed sign-in</h2><p>Google, Microsoft, and passkeys are selected on the managed portal, not inside this site.</p></div>
        <div><span className="strip-number">02</span><h2>Export in native tools</h2><p>Sign in to each provider yourself, then select and export only the logs or results you intend to review.</p></div>
        <div><span className="strip-number">03</span><h2>Import one JSON result</h2><p>Paste or upload a selected JSON object with explicit processing consent. Nothing is collected automatically.</p></div>
      </section>
      <section className="security-strip shell-width" aria-label="Open-source defensive toolkit">
        <div><span className="strip-number">LOCAL</span><h2>Audit a configuration, not a cloud account.</h2><p>Optional Terraform, Dockerfile and Compose checks run on one customer-selected file. Original MIT scanner by <a href="https://github.com/HuginnsHammer/CloudSentry" target="_blank" rel="noopener external">@HuginnsHammer</a>, preserved and credited.</p><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/config-auditor-integration.md" target="_blank" rel="noopener external">Read local audit instructions<ArrowUpRight size={15} aria-hidden="true" /></a></div>
        <div><span className="strip-number">EVIDENCE</span><h2>Explain the evidence. Preserve the unknowns.</h2><p>A separate opt-in local script produces a customer-readable packet with source hashes, descriptive text metrics and declared or unknown resource states. No identity, psychological or legal certainty is inferred.</p><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/customer-forensic-report.md" target="_blank" rel="noopener external">Read customer-report instructions<ArrowUpRight size={15} aria-hidden="true" /></a></div>
        <div><span className="strip-number">CREDIT</span><h2>Independent modules. Original creators.</h2><p>Creator handles, preserved licenses and pinned source identify what was integrated, what is only referenced and what remains unverified. This site never starts a local scanner, echo service or VM.</p><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/LINKS.md" target="_blank" rel="noopener external">Open all guides and creator references<ArrowUpRight size={15} aria-hidden="true" /></a></div>
      </section>
    </main>
  );
}

const navItems = [
  { href: "/workspace", label: "Workspace", icon: FolderOpen },
  { href: "/connections", label: "Provider profiles", icon: ShieldCheck },
  { href: "/manual-scans", label: "Manual workflow", icon: FileUp },
  { href: "/evidence", label: "Imported reports", icon: FileJson2 },
  { href: "/privacy", label: "Privacy", icon: ShieldCheck },
];

function AuthenticatedShell({ title, children }: { title: string; children: ReactNode }) {
  const { session, logout } = usePortal();
  const [location, navigate] = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [logoutError, setLogoutError] = useState(false);

  const handleLogout = async () => {
    setLogoutBusy(true);
    setLogoutError(false);
    const done = await logout();
    setLogoutBusy(false);
    if (done) navigate("/"); else setLogoutError(true);
  };

  return (
    <div className="app-frame">
      <header className="mobile-topbar"><Brand compact /><button className="button button--secondary mobile-menu" type="button" onClick={() => setNavOpen((open) => !open)}><Menu size={17} aria-hidden="true" />Menu</button></header>
      <aside className={`sidebar ${navOpen ? "sidebar--open" : ""}`} aria-label="Customer portal navigation">
        <div className="sidebar-brand"><Brand /></div>
        <nav>{navItems.map(({ href, label, icon: Icon }) => <Link href={href} className={`nav-link ${location === href ? "nav-link--active" : ""}`} key={href} onClick={() => setNavOpen(false)}><Icon size={17} aria-hidden="true" /><span>{label}</span></Link>)}</nav>
        <div className="sidebar-bottom">
          <div className="account-identity"><span className="account-provider">Managed session</span><strong>{session?.user?.name ?? ""}</strong>{session?.user?.email ? <span>{session.user.email}</span> : null}</div>
          {logoutError ? <ErrorMessage /> : null}
          <button className="button button--ghost logout-button" type="button" disabled={logoutBusy} onClick={() => void handleLogout()}>{logoutBusy ? <BusyLabel>Signing out</BusyLabel> : <><LogOut size={16} aria-hidden="true" />Sign out</>}</button>
        </div>
      </aside>
      <main className="portal-main"><div className="portal-heading"><p className="eyebrow">CloudSentry / customer workspace</p><h1>{title}</h1><IntegrationTrustNotice /></div>{children}</main>
    </div>
  );
}

function RequireSession({ title, children }: { title: string; children: ReactNode }) {
  const { session, loading, unavailable, refresh } = usePortal();
  if (loading) return <ServiceState title="Checking your managed session" detail="Loading the customer portal without processing provider data." />;
  if (unavailable) return <ServiceState title="Portal services are unavailable" detail={GENERIC_REQUEST_ERROR} retry={() => void refresh()} />;
  if (!session?.user) {
    return <main className="public-state shell-width"><Brand /><section className="state-card state-card--access"><ShieldCheck className="state-icon" size={27} aria-hidden="true" /><p className="eyebrow">Managed customer session required</p><h1>Sign in before opening {title.toLowerCase()}.</h1><p>This page remains closed until the API confirms an active managed session.</p><Link className="button button--primary" href="/">Go to managed sign-in<ChevronRight size={17} aria-hidden="true" /></Link></section></main>;
  }
  return <AuthenticatedShell title={title}>{children}</AuthenticatedShell>;
}

function useProfiles(enabled: boolean) {
  const [profiles, setProfiles] = useState<ProviderProfile[] | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [failed, setFailed] = useState(false);
  const load = useCallback(async () => {
    if (!enabled) {
      setProfiles(null);
      setLoading(false);
      setFailed(false);
      return;
    }
    setLoading(true);
    setFailed(false);
    try {
      const response = await api.profiles();
      setProfiles(response.profiles);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [enabled]);
  useEffect(() => { void load(); }, [load]);
  return { profiles, loading, failed, reload: load };
}

function useImportedReports(enabled: boolean) {
  const [reports, setReports] = useState<ImportedReportRecord[] | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [failed, setFailed] = useState(false);
  const load = useCallback(async () => {
    if (!enabled) {
      setReports(null);
      setLoading(false);
      setFailed(false);
      return;
    }
    setLoading(true);
    setFailed(false);
    try {
      const response = await api.importedReports();
      setReports(response.scans);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [enabled]);
  useEffect(() => { void load(); }, [load]);
  return { reports, loading, failed, reload: load };
}

function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{children}</section>;
}

function LoadingRow({ label }: { label: string }) {
  return <p className="loading-row"><LoaderCircle className="spin" size={16} aria-hidden="true" />{label}…</p>;
}

function WorkspacePage() {
  const { session } = usePortal();
  const signedIn = Boolean(session?.user);
  const profiles = useProfiles(signedIn);
  const reports = useImportedReports(signedIn);

  return (
    <RequireSession title="Workspace">
      <div className="content-column">
        <Panel className="workspace-intro"><div><p className="eyebrow">Manual evidence room</p><h2>Nothing is collected here.</h2><p>CloudSentry does not authenticate to cloud providers, scan accounts, probe networks, or collect logs. You make a selected export in the provider’s native tools, then explicitly import a JSON report.</p></div><Link className="button button--primary" href="/manual-scans">Open manual workflow<FileUp size={17} aria-hidden="true" /></Link></Panel>
        <div className="metric-pair">
          <Panel><p className="metric-label">Provider profiles</p>{profiles.loading ? <p className="metric-loading"><LoaderCircle className="spin" size={16} />Loading</p> : <strong className="metric-value">{profiles.profiles?.length ?? "—"}</strong>}<p className="muted-copy">Bookmarks and scope labels only. They do not authenticate or authorize this portal.</p>{profiles.failed ? <button className="text-button" type="button" onClick={() => void profiles.reload()}>Retry loading profiles</button> : null}</Panel>
          <Panel><p className="metric-label">Imported reports</p>{reports.loading ? <p className="metric-loading"><LoaderCircle className="spin" size={16} />Loading</p> : <strong className="metric-value">{reports.reports?.length ?? "—"}</strong>}<p className="muted-copy">Only JSON reports that you explicitly submitted from this managed customer session.</p>{reports.failed ? <button className="text-button" type="button" onClick={() => void reports.reload()}>Retry loading reports</button> : null}</Panel>
        </div>
        <Panel><div className="section-heading"><div><p className="eyebrow">Recent customer imports</p><h2>Imported reports only</h2></div><Link className="button button--secondary" href="/evidence">Open imported reports<ChevronRight size={16} aria-hidden="true" /></Link></div>{reports.loading ? <LoadingRow label="Loading imported reports" /> : null}{reports.failed ? <ErrorMessage /> : null}{!reports.loading && !reports.failed && reports.reports?.length === 0 ? <div className="empty-state"><FileJson2 size={22} aria-hidden="true" /><h3>No imported reports yet</h3><p>Use the manual workflow to export a result in native provider tools, then bring one selected JSON object to this portal.</p></div> : null}{!reports.loading && !reports.failed && reports.reports && reports.reports.length > 0 ? <ReportRows reports={reports.reports.slice(0, 4)} /> : null}</Panel>
      </div>
    </RequireSession>
  );
}

type ProfileFormState = { provider: "" | CloudProvider; label: string; scopeId: string; region: string; confirmed: boolean };
const emptyProfileForm = (): ProfileFormState => ({ provider: "", label: "", scopeId: "", region: "", confirmed: false });

function ProviderProfilesPage() {
  const { session } = usePortal();
  const { profiles, loading, failed, reload } = useProfiles(Boolean(session?.user));
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState<ProfileFormState>(emptyProfileForm);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ProviderProfile | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState(false);

  const update = <K extends keyof ProfileFormState>(key: K, value: ProfileFormState[K]) => setForm((current) => ({ ...current, [key]: value }));
  const resetForm = () => { setForm(emptyProfileForm()); setSaveError(false); setAdding(false); };

  const saveProfile = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!form.provider || !form.confirmed) return;
    setSaving(true);
    setSaveError(false);
    try {
      await api.createProfile(session?.csrfToken ?? null, {
        provider: form.provider,
        label: form.label.trim(),
        scopeId: form.scopeId.trim(),
        ...(form.region.trim() ? { region: form.region.trim() } : {}),
      });
      resetForm();
      await reload();
    } catch {
      setSaveError(true);
    } finally {
      setSaving(false);
    }
  };

  const removeProfile = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError(false);
    try {
      await api.removeProfile(session?.csrfToken ?? null, deleteTarget.id);
      setDeleteTarget(null);
      await reload();
    } catch {
      setDeleteError(true);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <RequireSession title="Provider profiles">
      <div className="content-column">
        <Panel><div className="section-heading section-heading--top-align"><div><p className="eyebrow">Customer-owned bookmark metadata</p><h2>Keep scope context, not cloud access.</h2><p className="muted-copy">A provider profile stores a label and scope reference that you supply. It is not an authenticated provider connection and the portal does not contact the provider when you save it.</p></div>{!adding ? <button className="button button--primary" type="button" onClick={() => setAdding(true)}><Plus size={17} aria-hidden="true" />Add provider profile</button> : null}</div>
          {adding ? <form className="profile-form" onSubmit={(event) => void saveProfile(event)}><div className="form-heading"><div><h3>New provider profile</h3><p>Keep the profile limited to a label, scope reference, and optional region. Values stay in this page until you save or cancel.</p></div><button className="button button--ghost" type="button" onClick={resetForm}><X size={16} aria-hidden="true" />Cancel</button></div><div className="field-grid"><label className="field"><span>Cloud provider</span><select value={form.provider} onChange={(event) => update("provider", event.target.value as "" | CloudProvider)} required><option value="">Select a provider</option>{CLOUD_PROVIDERS.map((provider) => <option key={provider} value={provider}>{providerName(provider)}</option>)}</select></label><label className="field"><span>Profile label</span><input value={form.label} onChange={(event) => update("label", event.target.value)} placeholder="e.g. Production workspace" autoComplete="off" required /></label><label className="field"><span>Scope ID or workspace reference</span><input value={form.scopeId} onChange={(event) => update("scopeId", event.target.value)} placeholder="Your selected scope reference" autoComplete="off" required /></label><label className="field"><span>Region or location (optional)</span><input value={form.region} onChange={(event) => update("region", event.target.value)} placeholder="e.g. us-east-1" autoComplete="off" /></label></div><label className="authorization-check"><input type="checkbox" checked={form.confirmed} onChange={(event) => update("confirmed", event.target.checked)} /><span>I confirm this is metadata only. Saving it grants no cloud access, does not authorize this portal, and does not include any provider authentication material.</span></label>{saveError ? <ErrorMessage /> : null}<div className="form-actions"><button className="button button--primary" type="submit" disabled={saving || !form.provider || !form.label.trim() || !form.scopeId.trim() || !form.confirmed || !session?.csrfToken}>{saving ? <BusyLabel>Saving profile</BusyLabel> : <><ShieldCheck size={16} aria-hidden="true" />Save provider profile</>}</button><button className="button button--secondary" type="button" disabled={saving} onClick={resetForm}>Cancel and clear</button></div></form> : null}
        </Panel>
        <Panel><div className="section-heading"><div><p className="eyebrow">Saved metadata</p><h2>Provider profiles</h2></div><button className="button button--secondary" type="button" disabled={loading} onClick={() => void reload()}><RefreshCw size={16} aria-hidden="true" />Refresh list</button></div>{loading ? <LoadingRow label="Loading provider profiles" /> : null}{failed ? <ErrorMessage /> : null}{!loading && !failed && profiles?.length === 0 ? <div className="empty-state"><ShieldCheck size={22} aria-hidden="true" /><h3>No provider profiles saved</h3><p>Profiles are optional. Add one only if a saved label and scope reference help organize your manual exports.</p></div> : null}{!loading && !failed && profiles && profiles.length > 0 ? <div className="record-list">{profiles.map((profile) => <article className="profile-row" key={profile.id}><div className="profile-row__title"><span className="provider-pill">{providerName(profile.provider)}</span><div><h3>{profile.label}</h3><p><span className="mono">{profile.scopeId}</span>{profile.region ? ` · ${profile.region}` : ""}</p></div></div><div className="profile-row__meta"><span className="status-label"><CheckCircle2 size={15} aria-hidden="true" />Metadata only</span><span>Saved {formatTime(profile.createdAt)}</span></div><button className="button button--danger" type="button" onClick={() => { setDeleteError(false); setDeleteTarget(profile); }}><Trash2 size={16} aria-hidden="true" />Delete profile</button></article>)}</div> : null}</Panel>
      </div>
      {deleteTarget ? <ConfirmDialog title="Delete this provider profile?" detail={`This removes the saved bookmark metadata for “${deleteTarget.label}”. It does not contact the provider, sign you out, revoke authorization, or change any cloud resource.`} confirmLabel="Delete profile" busy={deleting} error={deleteError} onCancel={() => setDeleteTarget(null)} onConfirm={() => void removeProfile()} /> : null}
    </RequireSession>
  );
}

function ConfirmDialog({ title, detail, confirmLabel, busy, error, onCancel, onConfirm }: { title: string; detail: string; confirmLabel: string; busy: boolean; error: boolean; onCancel: () => void; onConfirm: () => void }) {
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><p className="eyebrow">Confirmation required</p><h2 id="dialog-title">{title}</h2><p>{detail}</p>{error ? <ErrorMessage /> : null}<div className="modal-actions"><button className="button button--secondary" type="button" disabled={busy} onClick={onCancel}>Cancel</button><button className="button button--danger" type="button" disabled={busy} onClick={onConfirm}>{busy ? <BusyLabel>Working</BusyLabel> : confirmLabel}</button></div></section></div>;
}

function ReportRows({ reports, onOpen }: { reports: ImportedReportRecord[]; onOpen?: (reportId: number) => void }) {
  return <div className="report-list">{reports.map((report) => <article className="report-row" key={report.id}><div><span className="provider-pill">{providerName(report.provider)}</span><h3>Imported report <span className="mono">#{report.id}</span></h3><p>{formatTime(report.createdAt)} · <span className="mono">{report.status}</span></p></div><div className="report-row__actions"><span className={`summary-badge ${report.summaryAvailable ? "summary-badge--available" : ""}`}>{report.summaryAvailable ? "Summary available" : "No summary saved"}</span>{onOpen ? <button className="button button--secondary" type="button" onClick={() => onOpen(report.id)}>View report<ChevronRight size={16} aria-hidden="true" /></button> : null}</div></article>)}</div>;
}

function ManualWorkflowPage() {
  return (
    <RequireSession title="Manual workflow">
      <div className="content-column">
        <Panel className="workflow-intro"><p className="eyebrow">No provider authorization inside CloudSentry</p><h2>Use each provider’s native tools, then import one selected JSON result.</h2><p className="muted-copy">CloudSentry does not request provider authentication material, call provider dashboards, scan accounts, or scan networks. It receives only JSON you explicitly paste or choose to upload.</p><div className="workflow-steps"><div><span>01</span><p>Open the official provider dashboard and sign in through that provider’s own process.</p></div><div><span>02</span><p>Select and export only your own relevant logs or result JSON using the provider’s native export tools.</p></div><div><span>03</span><p>For an operating-system network result, use your own local tool and declare <span className="mono">local</span> during import. The portal performs no network discovery or host scanning.</p></div><div><span>04</span><p>Paste or upload the selected JSON on the Imported reports page, confirm processing, and decide separately whether to generate a summary.</p></div></div></Panel>
        <Panel><div className="section-heading"><div><p className="eyebrow">Official dashboards</p><h2>Open native provider tools</h2></div><Link className="button button--secondary" href="/connections">Manage provider profiles<ChevronRight size={16} aria-hidden="true" /></Link></div><div className="dashboard-grid">{PROVIDER_DASHBOARDS.map((dashboard) => <a className="dashboard-card" href={dashboard.href} target="_blank" rel="noopener external" key={dashboard.provider}><span className="provider-pill">{providerName(dashboard.provider)}</span><strong>{dashboard.label}</strong><p>{dashboard.detail}</p><span className="dashboard-card__link">Open official dashboard <ArrowUpRight size={15} aria-hidden="true" /></span></a>)}</div><p className="fine-print">These are ordinary external links. CloudSentry does not fetch, proxy, or act on their contents. A provider profile is optional bookmark metadata, not account authorization.</p></Panel>
        <Panel><p className="eyebrow">Local tools stay local</p><h2>Use your own local workflow for local results.</h2><p className="muted-copy">Customer-run OS or network tools remain outside this site. CloudSentry does not execute a CLI, inspect a web server, discover hosts, request DHCP or ARP data, or trust an IP address as an identity.</p><a className="documentation-link" href="https://github.com/1243353366/cloudsentry" target="_blank" rel="noopener external"><BookOpen size={16} aria-hidden="true" />Open local tool instructions<ArrowUpRight size={15} aria-hidden="true" /></a></Panel>
        <Panel>
          <p className="eyebrow">Credited, independently permission-gated modules</p>
          <h2>Inspect configuration. Explain selected evidence.</h2>
          <p>The optional static auditor preserves <a href="https://github.com/HuginnsHammer/CloudSentry" target="_blank" rel="noopener external">@HuginnsHammer’s MIT CloudSentry</a> separately from this portal. Install its isolated Python environment using the linked guide, then select one local regular file:</p>
          <pre className="report-code">{"python3 scripts/scan-configurations.py --target /absolute/path/to/Dockerfile --format json --consent"}</pre>
          <p>Exit 0 means no qualifying finding, 1 means findings and 2 means incomplete or denied. This is heuristic static analysis, not a security guarantee. It never runs Docker or Terraform. Review report evidence and paths for secrets before any manual import as provider <span className="mono">local</span>.</p>
          <pre className="report-code">{"python3 scripts/customer-forensic-report.py --text selected-content.txt --audit selected-audit.jsonl --output-dir new-private-customer-packet --consent"}</pre>
          <p>The customer-readable local packet links selected input hashes, UTC generation time, synthetic/observed evidence and descriptive writing metrics. Preserve its manifest pin separately. It does not identify an author, build a psychological dossier, prove unauthorized access, parse PDFs or submit evidence anywhere.</p>
          <p><strong>Compute policy review only:</strong> <span className="mono">python3 scripts/rationed-echo.py --review --consent</span>. CPU, memory, task and device-I/O limits require separately verified customer-side enforcement. No GPU workload or timeslice is granted. Missing enforcement remains unknown; contention is a review signal, not proof of intent. Standalone apply fails closed when trusted device-policy verification is unavailable.</p>
          <div className="form-actions"><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/config-auditor-integration.md" target="_blank" rel="noopener external">Audit setup and limitations<ArrowUpRight size={15} aria-hidden="true" /></a><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/customer-forensic-report.md" target="_blank" rel="noopener external">Customer packet guide<ArrowUpRight size={15} aria-hidden="true" /></a><a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/LINKS.md" target="_blank" rel="noopener external">All guides and creator credits<ArrowUpRight size={15} aria-hidden="true" /></a></div>
        </Panel>
        <Panel>
          <p className="eyebrow">Bounded defensive resource economics</p>
          <h2>Give an intrusion attempt no useful access. Keep your own work finite.</h2>
          <p className="muted-copy">The optional local decoy supplies synthetic state only. Its global input/output budgets, per-session input limits and rate controls stop work when quotas are exceeded. Nothing here launches a decoy, changes cloud resources, calls back to a visitor or imposes work on another device.</p>
          <p><strong>Your manual opt-in:</strong> choose an isolated environment you administer, explicitly start the loopback service and preserve its audit privately. Non-loopback exposure additionally needs your chosen bind address, <span className="mono">--allow-public</span> and independently reviewed ingress/egress controls. Website login or a scan result never opts you in. Any firewall or owned-domain DNS change remains a separate manual, reviewed action in your provider’s native tools.</p>
          <p>Default local service limits: 1 MiB total admitted input, 1 MiB reserved output, 64 KiB input per session, 10 commands/chunks per second and a 600-second service lifetime. CPU and memory enforcement require external container/runtime controls; these limits are not a cloud spending ceiling or a guarantee against compromise.</p>
          <h3>Bring a customer-generated operations report</h3>
          <p>On your own authorized machine, select one preserved decoy audit and run:</p>
          <pre className="report-code">{"python3 scripts/operations-summary.py --audit preserved-service-audit.jsonl --json"}</pre>
          <p>Save the JSON privately, review it, then import that selected report as provider <span className="mono">local</span>. Do not upload the raw JSONL audit here. Generating a portal summary still asks fresh permission; it does not re-run the local classifier.</p>
          <p className="disclaimer-copy">Connection-only, probe-like, burst, multi-command and execution-related text flags are low-confidence patterns in supplied records—not proof of an attacker, human operator, execution, real access or identity. Budget counters are unverified application reservations, not remote resource use or confirmed wire delivery. Missing records mean unknown coverage.</p>
          <p><strong>Emergency-only local option:</strong> <span className="mono">sh scripts/emergency-tarpit.sh --port 8023</span> starts a new silent, non-executing sink with fixed 30-second lifetime and low budgets. It does not take over existing sockets, interfere with OCR, repair a compromised host or start from this website. Isolate a suspected real host using a trusted provider/network control plane.</p>
          <a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/emergency.md" target="_blank" rel="noopener external"><BookOpen size={16} aria-hidden="true" />Read emergency opt-in and evidence instructions<ArrowUpRight size={15} aria-hidden="true" /></a>
          <div className="form-actions">
            <Link className="button button--primary" href="/evidence">Import selected report<FileUp size={16} aria-hidden="true" /></Link>
            <a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/resource-economics.md" target="_blank" rel="noopener external"><BookOpen size={16} aria-hidden="true" />Read resource-budget guide<ArrowUpRight size={15} aria-hidden="true" /></a>
          </div>
        </Panel>
        <Panel>
          <p className="eyebrow">Optional local BYOK • no hosted key vault</p>
          <h2>Extra visibility is your explicit choice.</h2>
          <p>Core tools and manual imports work without provider keys. For optional collection, run the local <span className="mono">collect-cloud</span> command on your authorized machine using customer-issued, least-privilege credentials and an explicit scope and time window. Do not paste keys into this website, reports, shell history or Git.</p>
          <div className="workflow-steps">
            <div><span>01</span><p><strong>Core-only mode:</strong> no provider credential is needed; a profile is bookmark metadata, not account access. Native exports can still be analyzed offline.</p></div>
            <div><span>02</span><p><strong>Customer-authorized integration:</strong> a local collector reports a bounded read-only response at a stated time. Imported status is an unverified declaration, not a live portal connection or permission audit.</p></div>
            <div><span>03</span><p><strong>Integration unavailable:</strong> missing credentials, transport/service/permission issues or unsupported input leave visibility unavailable or unknown. No shared-key fallback or automatic scan occurs.</p></div>
            <div><span>04</span><p><strong>Credential expired/revoked:</strong> shown as reported only with explicit local status; a generic authentication error or empty report does not prove expiry or revocation. Revoke/rotate natively, then rerun locally only if you choose.</p></div>
          </div>
          <p className="disclaimer-copy">Local collectors do not persist a provider key vault. Credentials remain in your process environment until you clear it; there is no guaranteed memory wipe. Read-only requests do not down-scope an overprivileged key. Revocation and cloud spending controls remain yours. Reduced credential custody does not eliminate legal responsibility.</p>
          <a className="documentation-link" href="https://github.com/1243353366/cloudsentry/blob/main/docs/integration-trust.md" target="_blank" rel="noopener external"><BookOpen size={16} aria-hidden="true" />Read permissions, opt-in and failure rules<ArrowUpRight size={15} aria-hidden="true" /></a>
        </Panel>
      </div>
    </RequireSession>
  );
}

function reportSection(summary: JsonObject, key: string): JsonValue | undefined {
  return key in summary ? summary[key] : undefined;
}

function SummaryDisplay({ summary, onRegenerate }: { summary: JsonObject; onRegenerate: () => void }) {
  const sections = [
    { title: "Observed tooling and decoy actions", key: "observed_tooling_and_decoy_actions" },
    { title: "Defensive review indicators", key: "defensive_review_indicators" },
    { title: "Legally relevant context", key: "legally_relevant_context" },
    { title: "Network boundary review", key: "network_boundary_review" },
  ];
  return <Panel className="summary-panel"><div className="section-heading"><div><p className="eyebrow">Optional bounded review</p><h2>Summary sections</h2></div><div className="report-row__actions"><span className="summary-badge summary-badge--available">Fresh approval requested</span><button className="button button--secondary" type="button" onClick={onRegenerate}>Generate again with fresh approval</button></div></div><p className="disclaimer-copy">Unknowns are not a skill assessment, identity attribution, legal proof, or a conclusion about complete coverage. Network boundary review is limited to customer-supplied configuration.</p><div className="summary-sections">{sections.map((section) => { const value = reportSection(summary, section.key); return <section className="summary-section" key={section.key}><h3>{section.title}</h3>{value === undefined ? <p>Unknown or not provided by this review.</p> : <pre>{jsonText(value)}</pre>}</section>; })}</div><details className="json-drawer"><summary>View bounded summary JSON</summary><pre>{jsonText(summary)}</pre></details></Panel>;
}

function SummaryConsentDialog({ reportId, csrfToken, onSkip, onCreated }: { reportId: number; csrfToken: string | null; onSkip: () => void; onCreated: (summary: JsonObject) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const generate = async () => {
    setBusy(true);
    setError(false);
    try {
      const response = await api.createSummary(csrfToken, reportId);
      const summary = isJsonObject(response) && "summary" in response && isJsonObject(response.summary) ? response.summary : response;
      if (!isJsonObject(summary)) throw new Error("SUMMARY_INVALID");
      onCreated(summary);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };
  return <div className="modal-backdrop" role="presentation"><section className="modal modal--summary" role="dialog" aria-modal="true" aria-labelledby="summary-dialog-title"><p className="eyebrow">Fresh permission for this imported report</p><h2 id="summary-dialog-title">Generate a bounded review summary?</h2><p>This is a separate request after your manual import. It sends <span className="mono">consent: true</span> for this report now; prior consent is never reused by this browser.</p><div className="summary-preview-list"><span>Observed tooling and decoy actions</span><span>Defensive review indicators</span><span>Legally relevant context</span><span>Network boundary review, when supplied</span></div>{error ? <ErrorMessage /> : null}<div className="modal-actions"><button className="button button--secondary" type="button" disabled={busy} onClick={onSkip}>Skip</button><button className="button button--primary" type="button" disabled={busy || !csrfToken} onClick={() => void generate()}>{busy ? <BusyLabel>Generating summary</BusyLabel> : <><FileJson2 size={16} aria-hidden="true" />Generate with fresh approval</>}</button></div></section></div>;
}

function downloadJson(filename: string, data: JsonObject) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function ReportPanel({ detail, label, onOpenSummary }: { detail: ImportedReportDetail; label: string; onOpenSummary: () => void }) {
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">("idle");
  const report = boundedReport(detail.report);
  const preparedJson = JSON.stringify(report, null, 2);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(preparedJson);
      setCopyStatus("copied");
    } catch {
      setCopyStatus("failed");
    }
  };

  return <div className="content-column"><IntegrationTrustNotice report={detail.report} /><Panel className="report-panel"><div className="section-heading section-heading--top-align"><div><p className="eyebrow">Bounded imported report</p><h2>Imported report <span className="mono">#{detail.scanId}</span></h2><p className="report-source"><ShieldCheck size={15} aria-hidden="true" />{label}</p></div><div className="report-actions"><button className="button button--secondary" type="button" onClick={() => void copy()}><Clipboard size={16} aria-hidden="true" />Copy filtered JSON</button><button className="button button--secondary" type="button" onClick={() => downloadJson(`cloudsentry-import-${detail.scanId}.json`, report)}><Download size={16} aria-hidden="true" />Download filtered JSON</button></div></div>{copyStatus === "copied" ? <p className="success-copy" role="status">Filtered report JSON copied.</p> : null}{copyStatus === "failed" ? <p className="validation-copy" role="status">Copy was unavailable in this browser. You can still download the filtered JSON.</p> : null}<p className="disclaimer-copy">The portal redacts credential-like fields and bounds this display. Imported JSON remains customer-supplied and unverified. A canonical JSON hash, if present in a report, is a processing reference—not raw-byte authentication, proof of origin, authorization, or an identity claim. Your original file remains outside this portal.</p><pre className="report-code">{preparedJson}</pre></Panel>{detail.summary ? <SummaryDisplay summary={detail.summary} onRegenerate={onOpenSummary} /> : <Panel className="summary-offer"><div><p className="eyebrow">Optional review</p><h2>No summary has been generated in this view.</h2><p>Generate one only with a new, explicit approval for this imported report.</p></div><button className="button button--primary" type="button" onClick={onOpenSummary}>Request summary<ChevronRight size={16} aria-hidden="true" /></button></Panel>}</div>;
}

function sourceProviderFromText(raw: string): ReportProvider | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return isJsonObject(parsed) && isReportProvider(parsed.provider) ? parsed.provider : null;
  } catch {
    return null;
  }
}

function ImportFormatGuidance() {
  const example = '{\n  "provider": "local",\n  "networks": [{ "cidr": "192.0.2.0/24" }],\n  "routes": []\n}';
  return <details className="format-guidance"><summary><Network size={16} aria-hidden="true" />Optional local network JSON format guidance</summary><div><p>This is a non-incident schema example only, not sample evidence, data analysis, proof, or a detection result. It is intentionally not prefilled into the import form.</p><pre>{example}</pre><p>A defensive network boundary review can only inspect customer-supplied CIDR and route configuration for overlaps, overly broad prefixes, or noncanonical network routes. Network masks do not authenticate an identity, detect activity, or make the review comprehensive. It performs no discovery, DHCP, ARP, probe, or IP-identity trust operation.</p></div></details>;
}

function ImportedReportsPage() {
  const { session } = usePortal();
  const signedIn = Boolean(session?.user);
  const { profiles, loading: profilesLoading, failed: profilesFailed } = useProfiles(signedIn);
  const { reports, loading: reportsLoading, failed: reportsFailed, reload: reloadReports } = useImportedReports(signedIn);
  const [rawReport, setRawReport] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [declaredProvider, setDeclaredProvider] = useState<"" | ReportProvider>("");
  const [authorized, setAuthorized] = useState(false);
  const [importing, setImporting] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);
  const [requestError, setRequestError] = useState(false);
  const [selected, setSelected] = useState<ImportedReportDetail | null>(null);
  const [selectedLabel, setSelectedLabel] = useState("Imported JSON — customer-supplied and unverified");
  const [selecting, setSelecting] = useState(false);
  const [selectionError, setSelectionError] = useState(false);
  const [summaryModal, setSummaryModal] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sourceProvider = useMemo(() => sourceProviderFromText(rawReport), [rawReport]);

  const resetInput = () => {
    setRawReport("");
    setSelectedProfileId("");
    setDeclaredProvider("");
    setAuthorized(false);
    setValidation(null);
    setRequestError(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const changeReport = (value: string) => {
    if (new Blob([value]).size > MAX_IMPORTED_REPORT_BYTES) {
      setValidation("The selected JSON exceeds the 1 MiB limit and was not accepted into this page.");
      return;
    }
    setRawReport(value);
    setValidation(null);
    setRequestError(false);
  };

  const chooseFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    if (file.size > MAX_IMPORTED_REPORT_BYTES) {
      setValidation("The selected JSON exceeds the 1 MiB limit and was not accepted into this page.");
      event.currentTarget.value = "";
      return;
    }
    try {
      changeReport(await file.text());
    } catch {
      setValidation("The selected file could not be read as a JSON import.");
    }
  };

  const importReport = async () => {
    setValidation(null);
    setRequestError(false);
    if (!authorized) {
      setValidation("Processing consent is required before the selected report can be imported.");
      return;
    }
    if (new Blob([rawReport]).size > MAX_IMPORTED_REPORT_BYTES) {
      setValidation("The selected JSON exceeds the 1 MiB limit.");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawReport);
    } catch {
      setValidation("Paste or upload one valid JSON object.");
      return;
    }
    if (!isJsonObject(parsed)) {
      setValidation("Paste or upload one JSON object.");
      return;
    }
    const sourceDeclaredProvider = isReportProvider(parsed.provider) ? parsed.provider : null;
    if (!sourceDeclaredProvider && !declaredProvider) {
      setValidation("Choose a declared report provider when the JSON does not contain a recognized provider.");
      return;
    }
    const importProvider: ReportProvider | undefined = sourceDeclaredProvider ? undefined : declaredProvider || undefined;
    setImporting(true);
    try {
      const response = await api.importReport(session?.csrfToken ?? null, parsed, importProvider);
      setSelected(response);
      setSelectedLabel(sourceDeclaredProvider
        ? "Imported JSON — provider representation came from the original customer file and is unverified"
        : `Imported JSON — declared provider “${providerName(importProvider as ReportProvider)}” selected by the customer; source remains unverified`);
      resetInput();
      setSummaryModal(true);
      await reloadReports();
    } catch {
      setRequestError(true);
    } finally {
      setImporting(false);
    }
  };

  const openReport = async (reportId: number) => {
    setSelecting(true);
    setSelectionError(false);
    try {
      const detail = await api.importedReport(reportId);
      setSelected(detail);
      setSelectedLabel("Imported JSON — customer-supplied and unverified");
      setSummaryModal(false);
    } catch {
      setSelectionError(true);
    } finally {
      setSelecting(false);
    }
  };

  const setSummary = (summary: JsonObject) => setSelected((current) => current ? { ...current, summary } : current);

  return (
    <RequireSession title="Imported reports">
      <div className="content-column">
        <Panel><p className="eyebrow">Bring one selected JSON result</p><h2>Paste or upload an export you chose outside this portal.</h2><p className="muted-copy">First sign in with the provider’s native process and export only your selected logs or local tool result. CloudSentry does not call a cloud provider, authorize a CLI, execute tools, or scan a web server or network.</p><Link className="documentation-link" href="/manual-scans"><BookOpen size={16} aria-hidden="true" />Read the manual workflow<ChevronRight size={15} aria-hidden="true" /></Link><div className="field-grid evidence-field"><label className="field"><span>Optional provider profile</span><select value={selectedProfileId} onChange={(event) => setSelectedProfileId(event.target.value)} disabled={profilesLoading || profilesFailed}><option value="">No provider profile selected</option>{(profiles ?? []).map((profile) => <option key={profile.id} value={profile.id}>{profile.label} · {providerName(profile.provider)}</option>)}</select><small>Profile selection is a local bookmark choice only; it is not sent as provider authorization.</small></label><label className="field"><span>Declared report provider</span><select value={declaredProvider} onChange={(event) => setDeclaredProvider(event.target.value as "" | ReportProvider)}><option value="">Use provider in JSON when present</option>{REPORT_PROVIDERS.map((provider) => <option key={provider} value={provider}>{providerName(provider)}{provider === "local" ? " (local OS/network result)" : ""}</option>)}</select><small>{sourceProvider ? `The JSON already declares ${providerName(sourceProvider)}. That original representation is not replaced.` : "Required when the JSON has no recognized provider. It is recorded as a customer declaration, not verification."}</small></label></div>{profilesFailed ? <p className="validation-copy">Provider profiles could not be loaded. You can still import without one.</p> : null}<label className="field evidence-field"><span>Selected report JSON (up to 1 MiB)</span><textarea value={rawReport} onChange={(event) => changeReport(event.target.value)} placeholder='{ "provider": "local", "networks": [], "routes": [] }' spellCheck="false" /></label><div className="upload-row"><label className="button button--secondary upload-button"><Upload size={16} aria-hidden="true" />Choose JSON file<input ref={fileInputRef} type="file" accept="application/json,.json" onChange={(event) => void chooseFile(event)} /></label><span className="fine-print">The selected file is read into this page before you explicitly import it.</span></div><ImportFormatGuidance /><label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I authorize server processing and retention of this selected customer-supplied JSON report.</span></label><p className="fine-print">The source is unverified. The portal cannot authenticate raw file bytes or prove source, authority, coverage, incident status, or identity. It retains the imported structured report privately only after this explicit import.</p>{validation ? <p className="validation-copy" role="alert">{validation}</p> : null}{requestError ? <ErrorMessage /> : null}<div className="form-actions"><button className="button button--primary" type="button" disabled={importing || !rawReport.trim() || !authorized || !session?.csrfToken} onClick={() => void importReport()}>{importing ? <BusyLabel>Importing selected report</BusyLabel> : <><FileJson2 size={16} aria-hidden="true" />Import selected JSON</>}</button><button className="button button--secondary" type="button" disabled={importing} onClick={resetInput}>Clear import form</button></div></Panel>
        <Panel><div className="section-heading"><div><p className="eyebrow">Customer imports</p><h2>Imported reports</h2></div><button className="button button--secondary" type="button" disabled={reportsLoading} onClick={() => void reloadReports()}><RefreshCw size={16} aria-hidden="true" />Refresh list</button></div>{reportsLoading ? <LoadingRow label="Loading imported reports" /> : null}{reportsFailed ? <ErrorMessage /> : null}{selectionError ? <ErrorMessage /> : null}{!reportsLoading && !reportsFailed && reports?.length === 0 ? <div className="empty-state"><FileJson2 size={22} aria-hidden="true" /><h3>No imported reports</h3><p>When you choose to import a selected JSON object, it will appear here for your managed customer session.</p></div> : null}{!reportsLoading && !reportsFailed && reports && reports.length > 0 ? <ReportRows reports={reports} onOpen={(id) => void openReport(id)} /> : null}{selecting ? <LoadingRow label="Opening selected report" /> : null}</Panel>
        {selected ? <ReportPanel detail={selected} label={selectedLabel} onOpenSummary={() => setSummaryModal(true)} /> : null}
      </div>
      {summaryModal && selected ? <SummaryConsentDialog reportId={selected.scanId} csrfToken={session?.csrfToken ?? null} onSkip={() => setSummaryModal(false)} onCreated={(summary) => { setSummary(summary); setSummaryModal(false); }} /> : null}
    </RequireSession>
  );
}

function PrivacyPage() {
  const { session, loading } = usePortal();
  const signedIn = Boolean(session?.user);
  const content = <div className="privacy-content"><p className="eyebrow">Product privacy statement</p><h1>What this customer portal handles</h1><p className="privacy-lede">This concise product statement describes the data used by CloudSentry’s customer portal. It is not a certification or a formal legal-policy claim.</p><div className="privacy-grid"><section><h2>Managed account identity</h2><p>The portal uses the identity returned by an active managed sign-in session. Google, Microsoft, and passkey choices occur on the managed portal; this site does not provide direct provider login.</p></section><section><h2>Provider profiles</h2><p>Provider profiles contain customer-supplied label, scope reference, optional region, and manual-profile status. They are metadata only, not authenticated cloud connections or access grants.</p></section><section><h2>Private imported reports</h2><p>The service privately retains JSON reports and optional summaries that you explicitly import with consent. Imported material remains customer-supplied and unverified source material.</p></section><section><h2>No cloud access storage</h2><p>The portal does not ask for, store, or use cloud-provider authentication material. It does not call a provider, collect logs, scan accounts, or perform network discovery.</p></section><section><h2>Explicit processing</h2><p>Import processing happens only after your explicit confirmation. A summary is a separate POST request with fresh approval; this browser does not save or reuse summary consent.</p></section><section><h2>Limits of conclusions</h2><p>Reports and summaries are bounded review aids. They do not prove legal facts, authorization, source authenticity, attribution, identity, compromise, or comprehensive coverage.</p></section></div></div>;
  if (loading) return <ServiceState title="Loading privacy statement" detail="Preparing portal information without contacting cloud providers." />;
  if (signedIn) return <AuthenticatedShell title="Privacy statement">{content}</AuthenticatedShell>;
  return <main className="privacy-page shell-width"><header className="landing-header"><Brand /><Link className="text-link" href="/">Managed sign-in<ChevronRight size={15} aria-hidden="true" /></Link></header>{content}</main>;
}

function NotFoundPage() {
  return <main className="public-state shell-width"><Brand /><section className="state-card"><p className="eyebrow">404</p><h1>That portal page is not available.</h1><p>Use the customer portal home to begin managed sign-in or open a listed page.</p><Link className="button button--primary" href="/">Return home<ChevronRight size={17} aria-hidden="true" /></Link></section></main>;
}

function AppRouter() {
  return <Switch><Route path="/" component={HomePage} /><Route path="/workspace" component={WorkspacePage} /><Route path="/connections" component={ProviderProfilesPage} /><Route path="/provider-profiles" component={ProviderProfilesPage} /><Route path="/manual-scans" component={ManualWorkflowPage} /><Route path="/evidence" component={ImportedReportsPage} /><Route path="/privacy" component={PrivacyPage} /><Route path="/404" component={NotFoundPage} /><Route component={NotFoundPage} /></Switch>;
}

export default function App() {
  return <PortalProvider><AppRouter /></PortalProvider>;
}
