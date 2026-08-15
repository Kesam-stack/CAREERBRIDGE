import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, NavLink, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { BadgeCheck, BriefcaseBusiness, Building2, CalendarClock, CheckCircle2, ChevronRight, ClipboardList, Copy, ExternalLink, KeyRound, Layers3, LockKeyhole, Search, ShieldCheck, Smartphone, Sparkles, UserRoundCheck, UsersRound, Webhook, XCircle } from "lucide-react";
import "./styles.css";

type User = { id: string; email: string; role: "candidate" | "employer" | "university" | "admin"; name: string };
type Job = { id: string; title: string; organization_name: string; location: string; work_mode: string; employment_type: string; compensation: string; description: string; skills: string; verification_requirements: string[] };
type Application = { id: string; title: string; organization_name?: string; candidate_name?: string; status: string; job_id: string };

const requirementLabels: Record<string, string> = {
  identity_verified: "Identity verified",
  education_credential: "Education credential",
  employment_credential: "Employment credential",
  work_authorization: "Work authorization",
  account_ownership: "Account ownership",
  income_verification: "Income verification",
  marketplace_uniqueness: "Marketplace uniqueness",
  custom_passid_credential: "Custom PASSID credential"
};
const employerRequirementKeys = ["identity_verified", "account_ownership", "income_verification"];
const privacyDataPermissions = [
  ["Identity", "Shared only after candidate consent"],
  ["Account ownership", "Ownership status only"],
  ["Income verification", "Status-only verification"],
];

function api(path: string, options: RequestInit = {}, csrf?: string) {
  return fetch(path, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...(options.headers ?? {})
    }
  });
}

function safeList<T>(value: T[] | undefined | null) {
  return Array.isArray(value) ? value : [];
}

function initials(name: string) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "CB";
}

function titleCase(value: string) {
  return value
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function authErrorMessage(body: any, fallback: string) {
  const known: Record<string, string> = {
    email_unavailable: "An account already exists with this email. Log in or use another email address.",
    organization_name_required: "Enter your registered organization name.",
    invalid_credentials: "The email or password is incorrect. If you do not have an account yet, create one first.",
    invalid_login: "Enter a valid email address and password.",
    signup_rate_limited: "Too many signup attempts were made from this network. Please wait and try again.",
    passid_session_rate_limited: "Too many PASSID sessions were requested. Please wait before trying again.",
    passid_already_connected: "PASSID is already connected for this application.",
    passid_identity_conflict: "This account needs identity review before PASSID can be used again.",
  };
  if (known[body?.error]) return known[body.error];
  const fieldMessages = Object.values(body?.fields ?? {}).flat().map(String);
  const validationMessages = fieldMessages.map((message) => {
    if (message.includes("at least 12")) return "Password must be at least 12 characters.";
    if (message === "password_requires_lowercase") return "Password must contain a lowercase letter.";
    if (message === "password_requires_uppercase") return "Password must contain an uppercase letter.";
    if (message === "password_requires_number") return "Password must contain a number.";
    if (message.includes("Invalid email")) return "Enter a valid email address.";
    if (message.includes("Invalid input: expected true")) return "Confirm the account-creation consent checkbox.";
    return message;
  });
  return validationMessages[0] ?? body?.message ?? fallback;
}

function passidCallbackMessage(result: string) {
  const messages: Record<string, string> = {
    success: "PASSID verification completed successfully.",
    partial_consent: "PASSID connected, but not every required permission was granted.",
    declined: "PASSID access was declined. You can start a new request when ready.",
    duplicate_identity: "This verified PASSID identity is already connected to another CareerBridge account.",
    identity_mismatch: "This CareerBridge account is already bound to a different verified PASSID identity.",
    identity_subject_missing: "PASSID did not return the institution identity reference required to prevent duplicate accounts.",
    already_connected: "PASSID is already connected for this application.",
    missing_code: "PASSID did not return the one-time authorization code.",
    retrieve_failed: "CareerBridge could not complete the PASSID authorization. Please try again.",
  };
  return messages[result] ?? `PASSID callback result: ${titleCase(result)}`;
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [csrf, setCsrf] = useState("");
  const [loading, setLoading] = useState(true);

  async function refresh() {
    const res = await api("/api/auth/me");
    const body = await res.json();
    setUser(body.user);
    setCsrf(body.csrf ?? "");
    setLoading(false);
  }

  useEffect(() => { refresh(); }, []);
  const value = useMemo(() => ({ user, csrf, refresh, setUser, setCsrf }), [user, csrf]);

  return (
    <BrowserRouter>
      <Shell auth={value} loading={loading}>
        <Routes>
          <Route path="/" element={<Landing auth={value} />} />
          <Route path="/signup" element={<Signup auth={value} />} />
          <Route path="/login" element={<Login auth={value} />} />
          <Route path="/dashboard" element={<CandidateDashboard auth={value} />} />
          <Route path="/profile" element={<Profile auth={value} />} />
          <Route path="/jobs" element={<Jobs auth={value} />} />
          <Route path="/jobs/:id" element={<JobDetail auth={value} />} />
          <Route path="/saved" element={<Placeholder title="Saved jobs" text="Saved roles are kept private to your CareerBridge account." />} />
          <Route path="/applications" element={<Applications auth={value} />} />
          <Route path="/verification" element={<Verification auth={value} />} />
          <Route path="/settings" element={<Settings auth={value} />} />
          <Route path="/employer/signup" element={<Signup auth={value} forcedRole="employer" />} />
          <Route path="/employer/login" element={<Login auth={value} />} />
          <Route path="/employer/dashboard" element={<EmployerDashboard auth={value} />} />
          <Route path="/employer/jobs" element={<EmployerJobs auth={value} />} />
          <Route path="/employer/jobs/new" element={<NewJob auth={value} />} />
          <Route path="/employer/jobs/:id/applicants" element={<Applications auth={value} employer />} />
          <Route path="/employer/applicants/:id" element={<ApplicantDetail auth={value} />} />
          <Route path="/employer/settings" element={<Settings auth={value} />} />
          <Route path="/admin/passid" element={<AdminPassid auth={value} />} />
          <Route path="*" element={<Placeholder title="Page not found" text="This CareerBridge route is not available." />} />
        </Routes>
      </Shell>
    </BrowserRouter>
  );
}

function Shell({ auth, loading, children }: { auth: any; loading: boolean; children: React.ReactNode }) {
  const navigate = useNavigate();
  async function logout() {
    const res = await api("/api/auth/logout", { method: "POST" }, auth.csrf);
    if (res.ok) {
      auth.setUser(null);
      auth.setCsrf("");
      await auth.refresh();
      navigate("/");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link className="brand" to="/">
          <span className="brand-mark">CB</span>
          <span><strong>CareerBridge</strong><small>Verified opportunity marketplace</small></span>
        </Link>
        <nav>
          <NavLink to="/jobs"><Search size={18} /> Jobs</NavLink>
          <NavLink to="/dashboard"><UserRoundCheck size={18} /> Candidate</NavLink>
          <NavLink to="/applications"><ClipboardList size={18} /> Applications</NavLink>
          <NavLink to="/verification"><ShieldCheck size={18} /> PASSID</NavLink>
          <NavLink to="/employer/dashboard"><Building2 size={18} /> Employer</NavLink>
          <NavLink to="/admin/passid"><Webhook size={18} /> Admin monitor</NavLink>
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={18} />
          <span>Identity and credential verification powered by PASSID.</span>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div className="topbar-user">
            <div className="avatar">{auth.user ? initials(auth.user.name) : "CB"}</div>
            <div>
              <strong>{loading ? "Loading workspace" : auth.user ? auth.user.name : "Welcome to CareerBridge"}</strong>
              <span>{auth.user ? `${titleCase(auth.user.role)} workspace` : "Independent institution demo"}</span>
            </div>
          </div>
          <div className="topbar-actions">
            <Link className="button secondary" to="/jobs">Browse jobs</Link>
            {auth.user ? (
              <>
                <Link className="button secondary" to="/settings">Settings</Link>
                <button className="button" onClick={logout}>Log out</button>
              </>
            ) : (
              <>
                <Link className="button secondary" to="/signup">Sign up</Link>
                <Link className="button" to="/login">Log in</Link>
              </>
            )}
          </div>
        </header>
        {children}
      </main>
    </div>
  );
}

function Landing({ auth }: { auth: any }) {
  return (
    <section className="landing">
      <div className="hero">
        <div className="hero-copy">
          <span className="eyebrow"><Sparkles size={16} /> Trusted hiring, consented data</span>
          <h1>CareerBridge</h1>
          <p>A production-style opportunity marketplace where candidates control PASSID-powered identity and credential verification before employers review applications.</p>
          <div className="hero-actions">
            <Link className="button" to="/jobs">Find opportunities <ChevronRight size={17} /></Link>
            <Link className="button secondary" to="/signup">Create account</Link>
            <Link className="button secondary" to="/employer/signup">Employer sign up</Link>
            <Link className="button secondary" to="/employer/dashboard">Employer workspace</Link>
          </div>
          <div className="hero-points">
            <div><CheckCircle2 size={16} /> Consent-first PASSID verification</div>
            <div><CheckCircle2 size={16} /> Role-based workspaces for candidates and employers</div>
            <div><CheckCircle2 size={16} /> No secret keys exposed in the browser</div>
          </div>
        </div>
        <div className="trust-panel">
          <h2>PASSID Connect flow</h2>
          {["Candidate applies", "CareerBridge creates session server-side", "Candidate approves hosted PASSID consent", "Employer sees permitted status only"].map((item, i) => (
            <div className="flow-row" key={item}><span>{i + 1}</span>{item}</div>
          ))}
        </div>
      </div>
      <div className="metric-grid">
        <Metric icon={<BriefcaseBusiness />} label="Roles" value="Jobs & internships" />
        <Metric icon={<BadgeCheck />} label="Verification" value="PASSID scoped consent" />
        <Metric icon={<LockKeyhole />} label="Security" value="Secret keys server-side" />
      </div>
      <div className="feature-grid">
        <FeatureCard title="Candidate control" text="Apply once, then approve the exact verification scopes requested for each role." />
        <FeatureCard title="Employer clarity" text="Every role lists what it needs up front, so applicants know what will be verified." />
        <FeatureCard title="Institution ready" text="Universities and administrators can support verified workflows without seeing secrets." />
      </div>
    </section>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return <div className="metric">{icon}<span>{label}</span><strong>{value}</strong></div>;
}

function Login({ auth }: { auth: any }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const res = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
    const body = await res.json();
    if (!res.ok) return setError(authErrorMessage(body, "Login failed. Please try again."));
    auth.setUser(body.user); auth.setCsrf(body.csrf);
    navigate(body.user.role === "employer" ? "/employer/dashboard" : body.user.role === "admin" ? "/admin/passid" : "/dashboard");
  }
  return <AuthCard title="Log in" onSubmit={submit} error={error}>
    <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
    <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
    <button className="button" type="submit">Log in</button>
    <p className="auth-link-row">No account yet? <Link to="/signup">Create one now</Link></p>
  </AuthCard>;
}

function Signup({ auth, forcedRole }: { auth: any; forcedRole?: string }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", role: forcedRole ?? "candidate", organization_name: "", website: "", accepted_terms: false });
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const payload = form.role === "candidate"
      ? { name: form.name, email: form.email, password: form.password, role: form.role, accepted_terms: form.accepted_terms }
      : form;
    const res = await api("/api/auth/signup", { method: "POST", body: JSON.stringify(payload) });
    const body = await res.json();
    if (!res.ok) return setError(authErrorMessage(body, "Signup failed. Check the form and try again."));
    auth.setUser(body.user);
    auth.setCsrf(body.csrf ?? "");
    navigate(body.user.role === "employer" ? "/employer/dashboard" : body.user.role === "admin" ? "/admin/passid" : "/dashboard");
  }
  return <AuthCard title={forcedRole === "employer" ? "Employer registration" : "Create your profile"} onSubmit={submit} error={error}>
    <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Full name" aria-label="Full name" required minLength={2} />
    <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="Email" type="email" required />
    <input value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Password (12+ characters, upper/lowercase and number)" type="password" required minLength={12} maxLength={128} />
    {!forcedRole && <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} required><option value="candidate">Candidate</option><option value="employer">Employer</option></select>}
    {form.role === "employer" && <>
      <input value={form.organization_name} onChange={(e) => setForm({ ...form, organization_name: e.target.value })} placeholder="Registered organization name" required minLength={2} />
      <input value={form.website} onChange={(e) => setForm({ ...form, website: e.target.value })} placeholder="Organization website (optional)" type="url" />
    </>}
    <label className="check-row"><input type="checkbox" checked={form.accepted_terms} onChange={(e) => setForm({ ...form, accepted_terms: e.target.checked })} required />I confirm these details are accurate and consent to account creation.</label>
    <button className="button" type="submit">Create account</button>
    <div className="notice">Employer organizations are created as pending and must be approved before publishing roles. PASSID institution access is configured separately with your registered Connect key.</div>
    <p className="auth-link-row">Already have an account? <Link to="/login">Log in</Link></p>
  </AuthCard>;
}

function AuthCard({ title, children, onSubmit, error }: { title: string; children: React.ReactNode; onSubmit: (e: React.FormEvent) => void; error: string }) {
  return <section className="center-panel"><form className="form-card" onSubmit={onSubmit}><h1>{title}</h1>{children}{error && <div className="error">{error}</div>}</form></section>;
}

function CandidateDashboard({ auth }: { auth: any }) {
  return <section className="page"><PageTitle title="Candidate dashboard" subtitle="Track profile readiness, applications, and PASSID verification." />
    <div className="grid-3">
      <ActionCard icon={<UserRoundCheck />} title="Profile" text="Education, experience, skills, and documents stay under your control." link="/profile" />
      <ActionCard icon={<BriefcaseBusiness />} title="Job search" text="Discover roles that disclose their PASSID requirements before you apply." link="/jobs" />
      <ActionCard icon={<ShieldCheck />} title="PASSID verification" text="Review requested categories and consent through hosted PASSID Connect." link="/verification" />
    </div>
  </section>;
}

function Profile({ auth }: { auth: any }) {
  const [profile, setProfile] = useState<any>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api("/api/profile")
      .then((r) => r.json())
      .then((body) => {
        if (body.error) {
          setError(body.error);
          return;
        }
        setProfile(body);
      })
      .catch(() => setError("Unable to load profile data."));
  }, []);
  return <section className="page"><PageTitle title="Profile" subtitle="Candidate profile data CareerBridge submits with applications." />
    <div className="grid-2">
      <div className="data-panel">{error ? <div className="error">{error}</div> : profile ? ["headline", "education", "experience", "skills"].map((key) => <label key={key}>{titleCase(key)}<textarea defaultValue={profile.profile?.[key] ?? ""} /></label>) : <LoadingBlock text="Loading profile data" />}</div>
      <aside className="side-panel"><h3>Data privacy</h3>{privacyDataPermissions.map(([name, detail]) => <div className="check-row" key={name}><ShieldCheck size={17} />{name}: {detail}</div>)}</aside>
    </div>
  </section>;
}

function Jobs({ auth }: { auth: any }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    setLoading(true);
    setError("");
    api(`/api/jobs?q=${encodeURIComponent(q)}`)
      .then((r) => r.json())
      .then((b) => {
        if (b.error) {
          setError(b.error);
          setJobs([]);
          return;
        }
        setJobs(safeList(b.jobs));
      })
      .catch(() => setError("Unable to load jobs right now."))
      .finally(() => setLoading(false));
  }, [q]);
  return <section className="page"><PageTitle title="Opportunity search" subtitle="Search jobs and internships with transparent PASSID requirements." />
    <div className="searchbar"><Search size={18} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, skill, company, location" /></div>
    {error && <div className="error">{error}</div>}
    <div className="job-list">{loading ? <LoadingBlock text="Loading opportunities" /> : jobs.length ? jobs.map((job) => <JobCard job={job} key={job.id} />) : <EmptyState title="No jobs found" text="Try a broader search or check back after employers publish new roles." action={<Link className="button secondary" to="/employer/jobs/new">Create a role</Link>} />}</div>
  </section>;
}

function JobCard({ job }: { job: Job }) {
  return <Link className="job-card" to={`/jobs/${job.id}`}>
    <div>
      <span className="pill">{job.employment_type}</span>
      <h2>{job.title}</h2>
      <p>{job.organization_name} · {job.location} · {job.work_mode}</p>
      <div className="pill-row"><span className="sub-pill">{job.compensation}</span></div>
    </div>
    <div className="checks">{safeList(job.verification_requirements).map((r) => <span key={r}><ShieldCheck size={14} />{requirementLabels[r] ?? r}</span>)}</div>
  </Link>;
}

function JobDetail({ auth }: { auth: any }) {
  const { id } = useParams();
  const [job, setJob] = useState<Job | null>(null);
  const [message, setMessage] = useState("");
  useEffect(() => { api(`/api/jobs/${id}`).then((r) => r.json()).then((b) => setJob(b.job)); }, [id]);
  async function apply() {
    const res = await api(`/api/jobs/${id}/apply`, { method: "POST", body: JSON.stringify({ cover_note: "Submitted from CareerBridge web." }) }, auth.csrf);
    const body = await res.json();
    setMessage(res.ok ? `Application ${body.id} submitted. PASSID verification may be required.` : body.error);
  }
  if (!job) return <Placeholder title="Loading job" text="Preparing the opportunity detail." />;
  return <section className="page detail-layout"><div><PageTitle title={job.title} subtitle={`${job.organization_name} · ${job.location}`} /><p className="body-copy">{job.description}</p><h3>Qualifications</h3><p className="body-copy">{job.skills}</p><div className="detail-actions"><button className="button" onClick={apply}>Apply for this role</button><Link className="button secondary" to="/jobs">Back to jobs</Link></div>{message && <div className="notice">{message}</div>}</div><aside className="side-panel"><h3>PASSID requirements</h3>{safeList(job.verification_requirements).length ? safeList(job.verification_requirements).map((r) => <div className="check-row" key={r}><CheckCircle2 size={17} />{requirementLabels[r] ?? r}</div>) : <div className="notice">No additional verification requirements are listed for this role.</div>}</aside></section>;
}

function Applications({ auth, employer = false }: { auth: any; employer?: boolean }) {
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { api("/api/applications").then((r) => r.json()).then((b) => setApps(safeList(b.applications))).finally(() => setLoading(false)); }, []);
  return <section className="page"><PageTitle title={employer ? "Applicant list" : "Applications"} subtitle="Status, verification state, and next actions." />
    <div className="table">{loading ? <LoadingBlock text="Loading applications" /> : apps.length ? apps.map((app) => <Link key={app.id} className="table-row" to={employer ? `/employer/applicants/${app.id}` : "/verification"}><span>{app.title}</span><span>{app.organization_name ?? app.candidate_name}</span><strong>{app.status}</strong></Link>) : <EmptyState title="No applications yet" text="Apply to a role to see your application and verification status here." action={<Link className="button secondary" to="/jobs">Browse jobs</Link>} />}</div>
  </section>;
}

function Verification({ auth }: { auth: any }) {
  const [apps, setApps] = useState<Application[]>([]);
  const [message, setMessage] = useState("");
  const [walletSession, setWalletSession] = useState<{ applicationTitle: string; hostedUrl: string; expiresAt?: string; requestedScopes: string[] } | null>(null);
  const [params] = useSearchParams();
  useEffect(() => { api("/api/applications").then((r) => r.json()).then((b) => setApps(safeList(b.applications))); }, []);
  async function verify(application: Application) {
    const res = await api("/api/passid/connect/sessions", { method: "POST", body: JSON.stringify({ application_id: application.id }) }, auth.csrf);
    const body = await res.json();
    if (!res.ok) return setMessage(authErrorMessage(body, "Unable to create PASSID session"));
    setMessage("");
    setWalletSession({
      applicationTitle: application.title,
      hostedUrl: body.hosted_url,
      expiresAt: body.expires_at,
      requestedScopes: safeList(body.requested_scopes),
    });
  }
  async function copyWalletLink() {
    if (!walletSession) return;
    await navigator.clipboard?.writeText(walletSession.hostedUrl);
    setMessage("PASSID wallet link copied.");
  }
  async function shareWalletLink() {
    if (!walletSession) return;
    if (navigator.share) {
      await navigator.share({ title: "PASSID verification", url: walletSession.hostedUrl });
      return;
    }
    await copyWalletLink();
  }
  return <section className="page"><PageTitle title="PASSID verification" subtitle="Review consent categories, open hosted PASSID Connect, and track access." />
    {params.get("result") && <div className="notice">{passidCallbackMessage(params.get("result")!)}</div>}
    {message && <div className="notice">{message}</div>}
    <div className="notice">Start verification from a CareerBridge application below. Sign-in, account creation, identity checks, and consent happen only on PassID's hosted authorization page.</div>
    {walletSession && <div className="wallet-panel">
      <div>
        <span className="eyebrow"><Smartphone size={15} /> PASSID Wallet</span>
        <h2>{walletSession.applicationTitle}</h2>
        <p>Open the secure PASSID session in your wallet, or share it to your phone without exposing any secret keys.</p>
        <div className="scope-list">{walletSession.requestedScopes.map((scope) => <span key={scope}>{scope}</span>)}</div>
      </div>
      <div className="wallet-actions">
        <a className="button" href={walletSession.hostedUrl} target="_blank" rel="noreferrer"><ExternalLink size={18} /> Open wallet</a>
        <button className="button secondary" type="button" onClick={shareWalletLink}><Smartphone size={18} /> Send to phone</button>
        <button className="button secondary" type="button" onClick={copyWalletLink}><Copy size={18} /> Copy link</button>
        {walletSession.expiresAt && <small>Expires {new Date(walletSession.expiresAt).toLocaleString()}</small>}
      </div>
    </div>}
    <div className="grid-2">{apps.length ? apps.map((app) => <div className="data-panel" key={app.id}><h2>{app.title}</h2><p>Status: {app.status}</p><p>CareerBridge requests only approved PASSID scopes for this application.</p><button className="button" onClick={() => verify(app)}>Continue with PASSID</button></div>) : <EmptyState title="No applications to verify" text="Apply to a role first, then return here to approve PASSID consent for that application." action={<Link className="button secondary" to="/jobs">Browse jobs</Link>} />}</div>
  </section>;
}

function EmployerDashboard({ auth }: { auth: any }) {
  return <section className="page"><PageTitle title="Employer dashboard" subtitle="Publish roles, review applicants, and request consented verification." />
    <div className="grid-3">
      <ActionCard icon={<BriefcaseBusiness />} title="Manage jobs" text="Create internships and full-time roles with explicit PASSID requirements." link="/employer/jobs" />
      <ActionCard icon={<UsersRound />} title="Applicants" text="Review candidates with only permitted verification results." link="/applications" />
      <ActionCard icon={<Layers3 />} title="Organization profile" text="Keep organization status and compliance details current." link="/employer/settings" />
    </div>
  </section>;
}

function EmployerJobs({ auth }: { auth: any }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { api("/api/employer/jobs").then((r) => r.json()).then((b) => setJobs(safeList(b.jobs))).finally(() => setLoading(false)); }, []);
  return <section className="page"><PageTitle title="Employer jobs" subtitle="Create and manage opportunities." /><Link className="button" to="/employer/jobs/new">Create job</Link>
    <div className="job-list">{loading ? <LoadingBlock text="Loading employer jobs" /> : jobs.length ? jobs.map((job) => <JobCard job={job} key={job.id} />) : <EmptyState title="No jobs published" text="Create your first role to start collecting qualified applicants." action={<Link className="button secondary" to="/employer/jobs/new">Create job</Link>} />}</div>
  </section>;
}

function NewJob({ auth }: { auth: any }) {
  const [created, setCreated] = useState("");
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const verification_requirements = fd.getAll("verification_requirements").map(String);
    const payload = Object.fromEntries(fd.entries()) as any;
    payload.verification_requirements = verification_requirements;
    const res = await api("/api/employer/jobs", { method: "POST", body: JSON.stringify(payload) }, auth.csrf);
    const body = await res.json();
    setCreated(res.ok ? `Created ${body.id}. It appears on your employer jobs page if published.` : body.error);
  }
  return <section className="page"><PageTitle title="Create job" subtitle="Choose only verification requirements supported by CareerBridge's PASSID package." />
    <form className="form-grid" onSubmit={submit}>
      <input name="title" placeholder="Job title" required />
      <input name="location" placeholder="Location" required />
      <select name="work_mode"><option>hybrid</option><option>remote</option><option>onsite</option></select>
      <select name="employment_type"><option>internship</option><option>full-time</option><option>part-time</option><option>contract</option></select>
      <input name="compensation" placeholder="Compensation" />
      <input name="deadline" placeholder="Deadline" />
      <textarea name="description" placeholder="Description" required />
      <textarea name="skills" placeholder="Required skills" />
      <div className="check-grid">{employerRequirementKeys.map((key) => <label key={key}><input type="checkbox" name="verification_requirements" value={key} defaultChecked={key === "identity_verified"} />{requirementLabels[key]}</label>)}</div>
      <select name="status"><option>draft</option><option>published</option></select>
      <button className="button" type="submit">Publish job</button>
      {created && <div className="notice">{created}</div>}
    </form>
  </section>;
}

function ApplicantDetail({ auth }: { auth: any }) {
  const { id } = useParams();
  const [detail, setDetail] = useState<any>(null);
  useEffect(() => { api(`/api/employer/applicants/${id}`).then((r) => r.json()).then(setDetail); }, [id]);
  const verification = detail?.passid_verification ?? {};
  return <section className="page"><PageTitle title="Applicant detail" subtitle="Verification results are status-oriented and scoped." />
    <div className="detail-layout"><div className="data-panel"><h2>{detail?.applicant?.candidate_name ?? "Applicant"}</h2><p>{detail?.applicant?.title}</p><p>Stage: {detail?.applicant?.status}</p></div>
      <aside className="side-panel"><h3>PASSID verification</h3>{["identity", "income", "account_ownership", "verification_status", "consent_status"].map((k) => <div className="check-row" key={k}><BadgeCheck size={17} />{titleCase(k)}: {verification[k] ?? "Not requested"}</div>)}</aside></div>
  </section>;
}

function AdminPassid({ auth }: { auth: any }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    if (auth.user?.role !== "admin") return;
    api("/api/admin/passid").then((r) => r.json()).then(setData);
  }, [auth.user?.role]);
  if (auth.user?.role !== "admin") {
    return <section className="page"><PageTitle title="PASSID integration monitor" subtitle="Admin access is required." /><div className="notice">Log in as a CareerBridge administrator to view sanitized PASSID connection and webhook records.</div></section>;
  }
  return <section className="page"><PageTitle title="PASSID integration monitor" subtitle="Environment, sessions, connections, webhooks, and sanitized audit visibility." />
    <div className="notice">No secret keys, identity references, or webhook secrets are displayed here. Bound identities: {data?.boundIdentityCount ?? 0}. Identity conflicts: {data?.identityConflictCount ?? 0}.</div>
    <div className="grid-2"><div className="data-panel"><h2>Connections</h2>{(data?.connections ?? []).map((c: any) => <p key={c.id}>{c.candidate_reference} · {c.status} · {c.consent_status}</p>)}</div><div className="data-panel"><h2>Webhook events</h2>{(data?.events ?? []).map((e: any) => <p key={e.id}>{e.type} · {e.id}</p>)}</div></div>
  </section>;
}

function Settings({ auth }: { auth: any }) {
  const [connections, setConnections] = useState<any[]>([]);
  const [message, setMessage] = useState("");
  async function refreshConnections() {
    if (auth.user?.role !== "candidate") return;
    const res = await api("/api/passid/connections");
    const body = await res.json();
    if (res.ok) setConnections(safeList(body.connections));
  }
  useEffect(() => { refreshConnections(); }, [auth.user?.role]);
  async function revoke(id: string) {
    const res = await api(`/api/passid/connections/${id}/revoke`, { method: "POST" }, auth.csrf);
    const body = await res.json();
    setMessage(res.ok ? "PASSID access revoked. Reconnect to verify this application again." : body.error ?? "Unable to revoke PASSID access.");
    if (res.ok) await refreshConnections();
  }
  return <section className="page"><PageTitle title="Settings" subtitle="Account, privacy, consent, and access management." />
    <div className="data-panel"><h2>Privacy and consent</h2><p>CareerBridge never receives your PASSID secret credentials. Candidates can revoke CareerBridge access, which requires a new PASSID Connect flow to restore.</p></div>
    {message && <div className="notice">{message}</div>}
    {auth.user?.role === "candidate" && <div className="data-panel"><h2>PASSID connections</h2>
      {connections.length ? connections.map((connection) => <div className="check-row" key={connection.id}>
        <span>{connection.title} · {connection.consent_status}</span>
        <button className="button secondary" type="button" disabled={connection.consent_status === "revoked"} onClick={() => revoke(connection.id)}>Revoke access</button>
      </div>) : <p>No PASSID connections are active for this account.</p>}
    </div>}
  </section>;
}

function PageTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return <div className="page-title"><h1>{title}</h1><p>{subtitle}</p></div>;
}

function ActionCard({ icon, title, text, link }: { icon: React.ReactNode; title: string; text: string; link: string }) {
  return <Link className="action-card" to={link}>{icon}<h2>{title}</h2><p>{text}</p><span>Open <ChevronRight size={15} /></span></Link>;
}

function FeatureCard({ title, text }: { title: string; text: string }) {
  return <div className="feature-card"><h3>{title}</h3><p>{text}</p></div>;
}

function LoadingBlock({ text }: { text: string }) {
  return <div className="loading-block" aria-live="polite"><span className="spinner" />{text}</div>;
}

function EmptyState({ title, text, action }: { title: string; text: string; action?: React.ReactNode }) {
  return <div className="empty-state"><h3>{title}</h3><p>{text}</p>{action}</div>;
}

function Placeholder({ title, text }: { title: string; text: string }) {
  return <section className="page"><PageTitle title={title} subtitle={text} /></section>;
}

createRoot(document.getElementById("root")!).render(<App />);
