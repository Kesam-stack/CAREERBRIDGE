import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, NavLink, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { BadgeCheck, BriefcaseBusiness, Building2, CalendarClock, CheckCircle2, ChevronRight, ClipboardList, KeyRound, Layers3, LockKeyhole, Search, ShieldCheck, Sparkles, UserRoundCheck, UsersRound, Webhook, XCircle } from "lucide-react";
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
  payout_readiness: "Payout readiness",
  income_verification: "Income verification",
  business_verification: "Business verification",
  marketplace_uniqueness: "Marketplace uniqueness",
  duplicate_account_risk: "Duplicate-account risk",
  custom_passid_credential: "Custom PASSID credential"
};

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
          <div>
            <strong>{loading ? "Loading..." : auth.user ? auth.user.name : "Welcome"}</strong>
            <span>{auth.user ? `${auth.user.role} workspace` : "Independent institution demo"}</span>
          </div>
          {auth.user ? <Link className="button secondary" to="/settings">Settings</Link> : <Link className="button" to="/login">Log in</Link>}
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
          <p>A production-style opportunity marketplace where candidates control PASSID-powered identity, credential, and financial-trust verification before employers review applications.</p>
          <div className="hero-actions">
            <Link className="button" to="/jobs">Find opportunities <ChevronRight size={17} /></Link>
            <Link className="button secondary" to="/employer/dashboard">Employer workspace</Link>
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
      {!auth.user && <DemoLogins />}
    </section>
  );
}

function DemoLogins() {
  return <div className="notice">Demo users: `amara@careerbridge.test`, `recruiter@careerbridge.test`, `admin@careerbridge.test` with password `CareerBridgeDemo!2026`.</div>;
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return <div className="metric">{icon}<span>{label}</span><strong>{value}</strong></div>;
}

function Login({ auth }: { auth: any }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("amara@careerbridge.test");
  const [password, setPassword] = useState("CareerBridgeDemo!2026");
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const res = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
    const body = await res.json();
    if (!res.ok) return setError(body.error ?? "Login failed");
    auth.setUser(body.user); auth.setCsrf(body.csrf);
    navigate(body.user.role === "employer" ? "/employer/dashboard" : body.user.role === "admin" ? "/admin/passid" : "/dashboard");
  }
  return <AuthCard title="Log in" onSubmit={submit} error={error}>
    <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
    <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
    <button className="button">Log in securely</button>
    <DemoLogins />
  </AuthCard>;
}

function Signup({ auth, forcedRole }: { auth: any; forcedRole?: string }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", role: forcedRole ?? "candidate" });
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const res = await api("/api/auth/signup", { method: "POST", body: JSON.stringify(form) });
    const body = await res.json();
    if (!res.ok) return setError(body.error ?? "Signup failed");
    navigate("/login");
  }
  return <AuthCard title={forcedRole === "employer" ? "Employer registration" : "Create your profile"} onSubmit={submit} error={error}>
    <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Full name" />
    <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="Email" />
    <input value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Password" type="password" />
    {!forcedRole && <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="candidate">Candidate</option><option value="employer">Employer</option><option value="university">University partner</option></select>}
    <button className="button">Create account</button>
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
  useEffect(() => { api("/api/profile").then((r) => r.json()).then(setProfile); }, []);
  return <section className="page"><PageTitle title="Profile" subtitle="Candidate profile data CareerBridge submits with applications." />
    <div className="data-panel">{profile ? ["headline", "education", "experience", "skills"].map((key) => <label key={key}>{key}<textarea defaultValue={profile.profile?.[key] ?? ""} /></label>) : "Loading..."}</div>
  </section>;
}

function Jobs({ auth }: { auth: any }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [q, setQ] = useState("");
  useEffect(() => { api(`/api/jobs?q=${encodeURIComponent(q)}`).then((r) => r.json()).then((b) => setJobs(b.jobs ?? [])); }, [q]);
  return <section className="page"><PageTitle title="Opportunity search" subtitle="Search jobs and internships with transparent PASSID requirements." />
    <div className="searchbar"><Search size={18} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, skill, company, location" /></div>
    <div className="job-list">{jobs.map((job) => <JobCard job={job} key={job.id} />)}</div>
  </section>;
}

function JobCard({ job }: { job: Job }) {
  return <Link className="job-card" to={`/jobs/${job.id}`}>
    <div><span className="pill">{job.employment_type}</span><h2>{job.title}</h2><p>{job.organization_name} · {job.location} · {job.work_mode}</p></div>
    <div className="checks">{job.verification_requirements.map((r) => <span key={r}><ShieldCheck size={14} />{requirementLabels[r] ?? r}</span>)}</div>
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
  return <section className="page detail-layout"><div><PageTitle title={job.title} subtitle={`${job.organization_name} · ${job.location}`} /><p className="body-copy">{job.description}</p><h3>Qualifications</h3><p className="body-copy">{job.skills}</p><button className="button" onClick={apply}>Apply for this role</button>{message && <div className="notice">{message}</div>}</div><aside className="side-panel"><h3>PASSID requirements</h3>{job.verification_requirements.map((r) => <div className="check-row" key={r}><CheckCircle2 size={17} />{requirementLabels[r] ?? r}</div>)}</aside></section>;
}

function Applications({ auth, employer = false }: { auth: any; employer?: boolean }) {
  const [apps, setApps] = useState<Application[]>([]);
  useEffect(() => { api("/api/applications").then((r) => r.json()).then((b) => setApps(b.applications ?? [])); }, []);
  return <section className="page"><PageTitle title={employer ? "Applicant list" : "Applications"} subtitle="Status, verification state, and next actions." />
    <div className="table">{apps.map((app) => <Link key={app.id} className="table-row" to={employer ? `/employer/applicants/${app.id}` : "/verification"}><span>{app.title}</span><span>{app.organization_name ?? app.candidate_name}</span><strong>{app.status}</strong></Link>)}</div>
  </section>;
}

function Verification({ auth }: { auth: any }) {
  const [apps, setApps] = useState<Application[]>([]);
  const [message, setMessage] = useState("");
  const [params] = useSearchParams();
  useEffect(() => { api("/api/applications").then((r) => r.json()).then((b) => setApps(b.applications ?? [])); }, []);
  async function verify(application_id: string) {
    const res = await api("/api/passid/connect/sessions", { method: "POST", body: JSON.stringify({ application_id }) }, auth.csrf);
    const body = await res.json();
    if (!res.ok) return setMessage(body.error ?? "Unable to create PASSID session");
    window.location.assign(body.hosted_url);
  }
  return <section className="page"><PageTitle title="PASSID verification" subtitle="Review consent categories, open hosted PASSID Connect, and track access." />
    {params.get("result") && <div className="notice">PASSID callback result: {params.get("result")}</div>}
    {message && <div className="error">{message}</div>}
    <div className="grid-2">{apps.map((app) => <div className="data-panel" key={app.id}><h2>{app.title}</h2><p>Status: {app.status}</p><p>CareerBridge requests only approved PASSID scopes for this application.</p><button className="button" onClick={() => verify(app.id)}>Continue with PASSID</button></div>)}</div>
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
  return <section className="page"><PageTitle title="Employer jobs" subtitle="Create and manage opportunities." /><Link className="button" to="/employer/jobs/new">Create job</Link><Jobs auth={auth} /></section>;
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
    setCreated(res.ok ? `Created ${body.id}` : body.error);
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
      <div className="check-grid">{Object.entries(requirementLabels).map(([key, label]) => <label key={key}><input type="checkbox" name="verification_requirements" value={key} defaultChecked={key === "identity_verified"} />{label}</label>)}</div>
      <select name="status"><option>draft</option><option>published</option></select>
      <button className="button">Publish job</button>
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
      <aside className="side-panel"><h3>PASSID verification</h3>{["identity", "education", "account_ownership", "marketplace_uniqueness", "consent_status"].map((k) => <div className="check-row" key={k}><BadgeCheck size={17} />{k.replace(/_/g, " ")}: {verification[k] ?? "Not requested"}</div>)}</aside></div>
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
    <div className="notice">No secret keys or webhook secrets are displayed here.</div>
    <div className="grid-2"><div className="data-panel"><h2>Connections</h2>{(data?.connections ?? []).map((c: any) => <p key={c.id}>{c.candidate_reference} · {c.status} · {c.consent_status}</p>)}</div><div className="data-panel"><h2>Webhook events</h2>{(data?.events ?? []).map((e: any) => <p key={e.id}>{e.type} · {e.id}</p>)}</div></div>
  </section>;
}

function Settings({ auth }: { auth: any }) {
  return <section className="page"><PageTitle title="Settings" subtitle="Account, privacy, consent, and access management." /><div className="data-panel"><h2>Privacy and consent</h2><p>CareerBridge never receives your PASSID secret credentials. Candidates can revoke CareerBridge access, which requires a new PASSID Connect flow to restore.</p></div></section>;
}

function PageTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return <div className="page-title"><h1>{title}</h1><p>{subtitle}</p></div>;
}

function ActionCard({ icon, title, text, link }: { icon: React.ReactNode; title: string; text: string; link: string }) {
  return <Link className="action-card" to={link}>{icon}<h2>{title}</h2><p>{text}</p><span>Open <ChevronRight size={15} /></span></Link>;
}

function Placeholder({ title, text }: { title: string; text: string }) {
  return <section className="page"><PageTitle title={title} subtitle={text} /></section>;
}

createRoot(document.getElementById("root")!).render(<App />);
