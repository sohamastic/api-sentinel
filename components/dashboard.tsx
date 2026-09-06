'use client';
import { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
  Activity,
  Radio,
  LockKeyhole,
  Terminal,
  ArrowUpRight,
  ArrowRight,
  Play,
  Check,
  X,
  Search,
  RefreshCw,
  ChevronRight,
  FileSearch,
  ShieldAlert,
  SlidersHorizontal,
  Eye,
  RotateCcw,
  LoaderCircle,
} from 'lucide-react';
import {
  RULES,
  ENDPOINTS,
  SCENARIOS,
  type Mode,
  type RuleId,
  type ScenarioId,
} from '../lib/security';
import type { EventRecord } from '../lib/store';
type Tab = 'Overview' | 'Events' | 'Endpoints' | 'Policies' | 'Playground';
type State = {
  events: EventRecord[];
  counts: {
    total: number;
    blocked: number;
    filtered: number;
    monitored: number;
    latency: number;
  };
  endpoints: {
    endpoint: string;
    method: string;
    requests: number;
    blocked: number;
    lastSeen: number;
  }[];
  series: { minute: number; total: number; blocked: number }[];
  audit: {
    id: string;
    at: number;
    rule: string;
    mode: string;
    reason: string;
  }[];
  policies: Record<RuleId, Mode>;
  now: number;
};
type Run = {
  scenario: string;
  title: string;
  responses: {
    status: number;
    action: string;
    requestId: string;
    body: unknown;
  }[];
  summary: { total: number; blocked: number; filtered: number };
};
async function api(path: string, body?: unknown) {
  const response = await fetch(`/api/console/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error((data as { error?: string }).error ?? 'Request failed.');
  return data;
}
const time = (at: number) =>
  new Date(at).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
function Badge({ action, label }: { action: string; label?: string }) {
  return (
    <span className={`badge ${action}`}>
      <span />
      {label ?? action}
    </span>
  );
}
const NAV = [
  { name: 'Overview', icon: Activity },
  { name: 'Events', icon: FileSearch },
  { name: 'Endpoints', icon: Radio },
  { name: 'Policies', icon: LockKeyhole },
  { name: 'Playground', icon: Terminal },
] as const;
const HEADINGS = {
  Overview: [
    'Traffic under control.',
    'Inspect API requests. Understand decisions. Tune protection.',
  ],
  Events: [
    'Every decision, explained.',
    'Inspect the latest 100 requests and the evidence behind each action.',
  ],
  Endpoints: [
    'Know your API surface.',
    'Four registered demo endpoints. Explicit contracts and enforcement.',
  ],
  Policies: [
    'Protection on your terms.',
    'Tune editable controls. Every policy change leaves an audit trail.',
  ],
  Playground: [
    'Put protection to the test.',
    'Run controlled scenarios through the same gateway used by direct requests.',
  ],
};
export default function Dashboard() {
  const [tab, setTab] = useState<Tab>('Overview'),
    [state, setState] = useState<State | null>(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(''),
    [notice, setNotice] = useState('');
  const [selected, setSelected] = useState<EventRecord | null>(null),
    [filter, setFilter] = useState('all'),
    [query, setQuery] = useState(''),
    [run, setRun] = useState<Run | null>(null);
  const [editing, setEditing] = useState<RuleId | null>(null),
    [mode, setMode] = useState<Mode>('block'),
    [reason, setReason] = useState('');
  const refresh = useCallback(async () => {
    try {
      const next = (await api('state')) as State;
      setState(next);
      setError('');
      return next;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }, []);
  useEffect(() => {
    if (!selected && !editing) return;
    const previous = document.activeElement as HTMLElement | null;
    const trap = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;
      const dialog = document.querySelector('dialog');
      const controls = dialog?.querySelectorAll<HTMLElement>(
        'button:not(:disabled), select, textarea, input, [tabindex="0"]',
      );
      if (!controls?.length) return;
      const first = controls[0],
        last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', trap);
    return () => {
      document.removeEventListener('keydown', trap);
      previous?.focus();
    };
  }, [selected, editing]);
  useEffect(() => {
    const initial = setTimeout(() => void refresh(), 0);
    const timer = setInterval(() => {
      if (!document.hidden) void refresh();
    }, 3000);
    return () => {
      clearTimeout(initial);
      clearInterval(timer);
    };
  }, [refresh]);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(''), 5000);
    return () => clearTimeout(timer);
  }, [notice]);
  useEffect(() => {
    const listener = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelected(null);
        setEditing(null);
      }
    };
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, []);
  const execute = useCallback(
    async (id: ScenarioId) => {
      setBusy(id);
      setError('');
      try {
        const result = (await api('run', { scenario: id })) as Run;
        setRun(result);
        await refresh();
        setNotice(
          `${result.title}: ${result.summary.total} request(s) inspected.`,
        );
        return result;
      } catch (e) {
        setError((e as Error).message);
        throw e;
      } finally {
        setBusy('');
      }
    },
    [refresh],
  );
  useEffect(() => {
    type Context = {
      registerTool: (
        tool: {
          name: string;
          title: string;
          description: string;
          inputSchema: object;
          annotations: { readOnlyHint: boolean; untrustedContentHint: boolean };
          execute: (input: unknown) => Promise<unknown>;
        },
        options: { signal: AbortSignal },
      ) => unknown;
    };
    const context = (document as Document & { modelContext?: Context })
      .modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    try {
      void Promise.resolve(
        context.registerTool(
          {
            name: 'run_security_demo_scenario',
            title: 'Run security demo scenario',
            description:
              'Run a predefined synthetic request through the security gateway, save its decisions, and display the result in the playground.',
            inputSchema: {
              type: 'object',
              properties: {
                scenario: { type: 'string', enum: SCENARIOS.map((s) => s.id) },
              },
              required: ['scenario'],
              additionalProperties: false,
            },
            annotations: { readOnlyHint: false, untrustedContentHint: false },
            async execute(input) {
              if (
                !input ||
                typeof input !== 'object' ||
                Object.keys(input).some((k) => k !== 'scenario') ||
                !SCENARIOS.some(
                  (s) => s.id === (input as { scenario?: unknown }).scenario,
                )
              )
                throw new Error('Choose a listed scenario.');
              setTab('Playground');
              const r = await execute(
                (input as { scenario: ScenarioId }).scenario,
              );
              return {
                scenario: r.scenario,
                ...r.summary,
                statuses: r.responses.map((r) => r.status),
              };
            },
          },
          { signal: lifecycle.signal },
        ),
      ).catch(() => {});
    } catch {
      /* Optional browser capability. */
    }
    return () => lifecycle.abort();
  }, [execute]);
  async function suite() {
    setBusy('suite');
    setError('');
    try {
      let total = 0;
      for (const s of SCENARIOS) {
        setBusy(`suite:${s.title}`);
        const result = (await api('run', { scenario: s.id })) as Run;
        setRun(result);
        total += result.summary.total;
        await refresh();
      }
      setNotice(`Demo suite complete. ${total} requests inspected.`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy('');
    }
  }
  async function savePolicy() {
    if (!editing) return;
    setBusy('policy');
    try {
      await api('policy', { id: editing, mode, reason });
      await refresh();
      setEditing(null);
      setReason('');
      setNotice('Policy updated and recorded in the audit trail.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy('');
    }
  }
  async function review(event: EventRecord) {
    setBusy('review');
    try {
      await api('review', { id: event.id });
      setSelected({ ...event, reviewed: 1 });
      await refresh();
      setNotice('Event marked as reviewed.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy('');
    }
  }
  const counts = state?.counts,
    events = (state?.events ?? []).filter(
      (e) =>
        (filter === 'all' || e.action === filter) &&
        `${e.endpoint} ${e.identity} ${e.findings.map((f) => f.title).join(' ')}`
          .toLowerCase()
          .includes(query.toLowerCase()),
    );
  function eventTable(limit = 100) {
    return (
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Request / endpoint</th>
              <th>Decision</th>
              <th>Signal</th>
              <th>Time</th>
              <th>
                <span className="sr-only">Details</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, limit).map((e) => (
              <tr key={e.id}>
                <td>
                  <span
                    className={`method ${e.method === 'POST' ? 'post' : ''}`}
                  >
                    {e.method}
                  </span>
                  <code>{e.endpoint}</code>
                  <small>
                    {e.identity} ·{' '}
                    {e.scenario ? 'Demo scenario' : 'Direct request'}{' '}
                    {e.reviewed ? '· Reviewed' : ''}
                  </small>
                </td>
                <td>
                  <Badge action={e.action} />
                </td>
                <td>
                  <span className="signal-text">
                    {e.findings[0]?.title ?? 'All checks passed'}
                  </span>
                  <small>
                    HTTP {e.status} · {e.duration} ms
                  </small>
                </td>
                <td className="time-cell">{time(e.at)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={`Inspect request ${e.id}`}
                    onClick={(ev) => {
                      ev.stopPropagation();
                      setSelected(e);
                    }}
                  >
                    <ChevronRight size={18} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!events.length && (
          <div className="empty">
            <FileSearch size={30} />
            <h3>
              {state
                ? 'No matching requests yet'
                : 'Connecting to your gateway'}
            </h3>
            <p>
              {state
                ? 'Run a demo scenario to generate security events.'
                : 'The activity stream will appear when the service responds.'}
            </p>
            {state && (
              <button
                className="button secondary"
                onClick={() => setTab('Playground')}
              >
                Open playground <ArrowRight size={16} />
              </button>
            )}
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="shell">
      <aside inert={!!selected || !!editing}>
        <button
          className="brand"
          type="button"
          onClick={(e) => {
            e.preventDefault();
            setTab('Overview');
          }}
          aria-label="Sentinel overview"
        >
          <ShieldCheck />
          <span>
            sentinel<span className="brand-dot">.</span>
          </span>
        </button>
        <div className="workspace">
          WORKSPACE
          <br />
          <strong>
            <span className="workspace-avatar">S</span> API Security Lab
          </strong>
        </div>
        <div className="nav-label">MONITOR & PROTECT</div>
        <nav aria-label="Main navigation">
          {NAV.map(({ name, icon: Icon }) => (
            <button
              key={name}
              aria-current={tab === name ? 'page' : undefined}
              className={`nav-item ${tab === name ? 'active' : ''}`}
              onClick={() => {
                setTab(name);
                setSelected(null);
              }}
            >
              <Icon size={19} />
              {name}
              {name === 'Events' && !!counts?.blocked && (
                <span className="nav-count">{counts.blocked}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={22} />
          <strong>Understand the why.</strong>
          <p>Every blocked request has evidence you can inspect.</p>
        </div>
        <div className="sidebar-bottom">
          <span className="dot" /> Controlled demo environment
          <br />
          <span className="version">SENTINEL / v1.0</span>
        </div>
      </aside>
      <main inert={!!selected || !!editing}>
        <header>
          <div className="breadcrumbs">
            Workspace <ChevronRight size={14} />
            <span>{tab}</span>
          </div>
          <div className="header-right">
            <span className="tag">DEMO ENVIRONMENT</span>
            <div className="avatar">S</div>
          </div>
        </header>
        <section className="content">
          <div className="page-heading">
            <div>
              <p className="eyebrow">SECURITY OPERATIONS</p>
              <h1>{HEADINGS[tab][0]}</h1>
              <p className="muted">{HEADINGS[tab][1]}</p>
            </div>
            <button
              className="button primary"
              disabled={!!busy || !state}
              onClick={() => void suite()}
            >
              {busy.startsWith('suite') ? (
                <LoaderCircle size={16} className="spin" />
              ) : (
                <Play size={16} />
              )}
              Run demo suite
            </button>
          </div>
          {error && (
            <div className="error-banner" role="alert">
              <ShieldAlert size={18} />
              <span>{error}</span>
              <button onClick={() => void refresh()}>Retry connection</button>
            </div>
          )}
          {notice && (
            <output className="toast">
              <Check size={17} />
              {notice}
              <button
                className="icon-button"
                onClick={() => setNotice('')}
                aria-label="Dismiss notification"
              >
                <X size={15} />
              </button>
            </output>
          )}
          {busy.startsWith('suite:') && (
            <output className="progress-note">
              <LoaderCircle size={15} className="spin" /> Running{' '}
              {busy.slice(6)}…
            </output>
          )}
          {tab === 'Overview' && (
            <>
              <div className="stats">
                {[
                  {
                    label: 'Requests inspected',
                    value: counts?.total,
                    foot: 'All recorded traffic',
                    icon: Activity,
                  },
                  {
                    label: 'Threats blocked',
                    value: counts?.blocked,
                    foot: counts?.total
                      ? `${Math.round((counts.blocked / counts.total) * 100)}% of inspected requests`
                      : 'No blocked requests yet',
                    icon: ShieldAlert,
                  },
                  {
                    label: 'Responses filtered',
                    value: counts?.filtered,
                    foot: 'Restricted fields removed',
                    icon: Eye,
                  },
                  {
                    label: 'Protected endpoints',
                    value: 4,
                    foot: 'Across 6 security controls',
                    icon: Radio,
                  },
                ].map((s, i) => (
                  <div className={`stat stat-${i}`} key={s.label}>
                    <span>
                      {s.label}
                      <s.icon size={17} />
                    </span>
                    <strong>
                      {s.value === undefined ? '—' : s.value.toLocaleString()}
                    </strong>
                    <small>{s.foot}</small>
                  </div>
                ))}
              </div>
              <div className="overview-grid">
                <div className="panel activity-panel">
                  <div className="panel-title">
                    <h2>Traffic activity</h2>
                    <span className="muted">Last 30 minutes</span>
                  </div>
                  <div className="chart-legend">
                    <span>
                      <i />
                      Inspected
                    </span>
                    <span>
                      <i />
                      Blocked
                    </span>
                    <span className="live-indicator">
                      <span className="dot" />
                      {error ? 'Connection interrupted' : 'Refreshes every 3s'}
                    </span>
                  </div>
                  <TrafficChart state={state} />
                </div>
                <div className="panel posture">
                  <div className="panel-title">
                    <h2>Protection status</h2>
                    <ShieldCheck size={18} color="#c4f46b" />
                  </div>
                  <div
                    className="posture-ring"
                    style={{
                      background: `conic-gradient(#c4f46b ${(RULES.filter((r) => r.locked || state?.policies[r.id] === 'block').length / 6) * 100}%, #28313e 0)`,
                    }}
                  >
                    <div>
                      <strong>
                        {state
                          ? RULES.filter(
                              (r) =>
                                r.locked || state.policies[r.id] === 'block',
                            ).length
                          : '—'}
                        <span>/6</span>
                      </strong>
                      <small>enforcing</small>
                    </div>
                  </div>
                  <div className="posture-label">
                    {state &&
                    Object.values(state.policies).every((v) => v === 'block')
                      ? 'All controls enforcing'
                      : 'Review your policy modes'}
                  </div>
                  <button
                    className="text-button"
                    onClick={() => setTab('Policies')}
                  >
                    Manage policies <ArrowUpRight size={16} />
                  </button>
                </div>
              </div>
              <div className="panel">
                <div className="panel-title">
                  <div className="title-with-count">
                    <h2>Recent decisions</h2>
                    <span className="count-pill">
                      {state?.events.length ?? 0}
                    </span>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => setTab('Events')}
                  >
                    View all events <ArrowRight size={15} />
                  </button>
                </div>
                {eventTable(6)}
              </div>
              <div className="callout">
                <Terminal />
                <div>
                  <h3>A security lab, ready to run</h3>
                  <p>
                    Test cross-user access, expired tokens, injection patterns,
                    and request bursts with synthetic data.
                  </p>
                </div>
                <button
                  className="text-button"
                  onClick={() => setTab('Playground')}
                >
                  Open playground <ArrowUpRight size={18} />
                </button>
              </div>
            </>
          )}
          {tab === 'Events' && (
            <>
              <div className="toolbar">
                <div className="filter-tabs">
                  {['all', 'blocked', 'filtered', 'monitored', 'allowed'].map(
                    (f) => (
                      <button
                        key={f}
                        className={filter === f ? 'chosen' : ''}
                        onClick={() => setFilter(f)}
                      >
                        {f}
                      </button>
                    ),
                  )}
                </div>
                <label className="search-input">
                  <Search size={17} />
                  <input
                    placeholder="Search endpoint or signal…"
                    aria-label="Search events"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </label>
              </div>
              <div className="panel">{eventTable()}</div>
              <p className="footnote">
                Evidence is redacted. Bearer tokens, request bodies, and
                sensitive response values are never stored in the event stream.
              </p>
            </>
          )}
          {tab === 'Endpoints' && (
            <>
              <div className="inventory-note">
                <Radio size={19} />
                <span>
                  Base path: <code>/api/gateway</code>
                </span>
                <span className="tag green">DENY UNKNOWN ROUTES</span>
              </div>
              <div className="endpoint-grid">
                {ENDPOINTS.map((ep) => {
                  const stats = state?.endpoints.find(
                    (e) => e.endpoint === ep.path && e.method === ep.method,
                  );
                  return (
                    <article
                      className="panel endpoint-card"
                      key={ep.method + ep.path}
                    >
                      <div className="endpoint-heading">
                        <span
                          className={`method ${ep.method === 'POST' ? 'post' : ''}`}
                        >
                          {ep.method}
                        </span>
                        <code>{ep.path}</code>
                        <LockKeyhole size={16} />
                      </div>
                      <p className="muted">{ep.description}</p>
                      <div className="rule-chips">
                        {ep.rules.map((r) => (
                          <span key={r}>
                            {RULES.find((rule) => rule.id === r)?.title}
                          </span>
                        ))}
                      </div>
                      <div className="endpoint-metrics">
                        <div>
                          <strong>{stats?.requests ?? 0}</strong>
                          <span>requests</span>
                        </div>
                        <div>
                          <strong>{stats?.blocked ?? 0}</strong>
                          <span>blocked</span>
                        </div>
                        <div>
                          <strong>{stats ? time(stats.lastSeen) : '—'}</strong>
                          <span>last seen</span>
                        </div>
                      </div>
                      <div className="response-contract">
                        <span>Response contract</span>
                        <code>{ep.fields}</code>
                      </div>
                    </article>
                  );
                })}
              </div>
              <p className="footnote">
                Explicit inventory of configured demo routes. Automatic endpoint
                discovery and third-party API scanning are outside this
                version’s scope.
              </p>
            </>
          )}
          {tab === 'Policies' && (
            <>
              <div className="policy-note">
                <LockKeyhole size={18} />
                <p>
                  Authentication, ownership, and request contracts always
                  enforce. Monitor mode records a signal and lets the synthetic
                  request or response continue.
                </p>
              </div>
              <div className="panel policy-list">
                {RULES.map((rule) => (
                  <div className="policy-row" key={rule.id}>
                    <div className={`rule-icon ${rule.locked ? 'locked' : ''}`}>
                      {rule.locked ? (
                        <LockKeyhole size={20} />
                      ) : (
                        <SlidersHorizontal size={20} />
                      )}
                    </div>
                    <div className="policy-copy">
                      <span className="policy-category">{rule.category}</span>
                      <h3>{rule.title}</h3>
                      <p>{rule.description}</p>
                    </div>
                    <Badge
                      label={
                        state?.policies[rule.id] === 'monitor'
                          ? 'Monitoring'
                          : 'Enforcing'
                      }
                      action={
                        state?.policies[rule.id] === 'monitor'
                          ? 'monitored'
                          : 'allowed'
                      }
                    />
                    {rule.locked ? (
                      <span className="locked-label">Required</span>
                    ) : (
                      <button
                        className="button secondary small"
                        disabled={!state || !!busy}
                        onClick={() => {
                          setEditing(rule.id);
                          setMode(state?.policies[rule.id] ?? 'block');
                          setReason('');
                        }}
                      >
                        Configure
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <div className="panel">
                <div className="panel-title">
                  <h2>Policy & review audit trail</h2>
                  <span className="muted">Latest 30 changes</span>
                </div>
                {!state?.audit.length ? (
                  <div className="empty compact">
                    <p>
                      No changes yet. All controls start in enforcement mode.
                    </p>
                  </div>
                ) : (
                  <div className="audit-list">
                    {state.audit.map((a) => (
                      <div key={a.id}>
                        <span className="audit-dot" />
                        <div>
                          <strong>
                            {RULES.find((r) => r.id === a.rule)?.title ??
                              'Event review'}{' '}
                            <span className="muted">→ {a.mode}</span>
                          </strong>
                          <p>{a.reason}</p>
                        </div>
                        <time>{time(a.at)}</time>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
          {tab === 'Playground' && (
            <>
              <div className="playground-note">
                <Terminal size={19} />
                <p>
                  Each scenario starts with an isolated rate budget and uses
                  current policies. Expected outcomes assume enforcement. Replay
                  regenerates the predefined demo request.
                </p>
              </div>
              <div className="playground-layout">
                <div className="scenario-grid">
                  {SCENARIOS.map((s) => (
                    <article className="scenario-card" key={s.id}>
                      <div className="scenario-category">
                        {s.group}
                        <span className="method">{s.method}</span>
                      </div>
                      <h3>{s.title}</h3>
                      <p>{s.description}</p>
                      <div className="scenario-bottom">
                        <small>{s.expected}</small>
                        <button
                          className="icon-button run-button"
                          aria-label={`Run ${s.title}`}
                          disabled={!!busy || !state}
                          onClick={() => void execute(s.id).catch(() => {})}
                        >
                          {busy === s.id ? (
                            <LoaderCircle size={17} className="spin" />
                          ) : (
                            <Play size={17} />
                          )}
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
                <div className="panel result-panel">
                  <div className="panel-title">
                    <h2>Response inspector</h2>
                    <Terminal size={18} />
                  </div>
                  {!run ? (
                    <div className="empty">
                      <Terminal size={30} />
                      <h3>Awaiting your first scenario</h3>
                      <p>
                        Choose a scenario to inspect the gateway’s actual
                        response.
                      </p>
                    </div>
                  ) : (
                    <div className="result-body">
                      <span className="eyebrow">SCENARIO RESULT</span>
                      <h3>{run.title}</h3>
                      <div className="result-summary">
                        <div>
                          <strong>{run.summary.total}</strong>
                          <span>requests</span>
                        </div>
                        <div>
                          <strong>{run.summary.blocked}</strong>
                          <span>blocked</span>
                        </div>
                        <div>
                          <strong>{run.summary.filtered}</strong>
                          <span>filtered</span>
                        </div>
                      </div>
                      <div className="result-responses">
                        {run.responses.map((r, i) => (
                          <div className="response-item" key={r.requestId}>
                            <div>
                              <span className="mono">
                                #{String(i + 1).padStart(2, '0')}{' '}
                                <b>{r.status}</b>
                              </span>
                              <Badge action={r.action} />
                            </div>
                            <pre>{JSON.stringify(r.body, null, 2)}</pre>
                            <button
                              className="text-button"
                              onClick={() => {
                                const event = state?.events.find(
                                  (e) => e.id === r.requestId,
                                );
                                if (event) setSelected(event);
                                else
                                  setNotice(
                                    'This event is outside the latest 100 requests.',
                                  );
                              }}
                            >
                              Explain decision <ArrowRight size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
          <footer>
            <span>
              <span className="dot" /> API Sentinel
            </span>
            <span>Synthetic data · Private operator workspace</span>
            <button className="text-button" onClick={() => void refresh()}>
              <RefreshCw size={13} />
              Refresh
            </button>
          </footer>
        </section>
      </main>
      {selected && (
        <div className="drawer-backdrop">
          <dialog
            open
            className="event-drawer"
            aria-modal="true"
            aria-label="Decision details"
          >
            <div className="panel-title">
              <h2>Decision details</h2>
              <button
                className="icon-button"
                autoFocus
                onClick={() => setSelected(null)}
                aria-label="Close decision details"
              >
                <X size={21} />
              </button>
            </div>
            <div className="drawer-content">
              <Badge action={selected.action} />
              <h2 className="drawer-title">
                {selected.findings[0]?.title ?? 'All checks passed'}
              </h2>
              <div className="request-line">
                <span className="method">{selected.method}</span>
                <code>{selected.endpoint}</code>
              </div>
              <dl>
                {[
                  ['Identity', selected.identity],
                  ['HTTP status', selected.status],
                  ['Inspected at', new Date(selected.at).toLocaleString()],
                  ['Evaluation time', `${selected.duration} ms`],
                  ['Request ID', selected.id],
                ].map(([k, v]) => (
                  <div key={k}>
                    <dt>{k}</dt>
                    <dd className="wrap">{v}</dd>
                  </div>
                ))}
              </dl>
              <h3>Why this action?</h3>
              {selected.findings.length ? (
                selected.findings.map((f, i) => (
                  <div className="finding" key={i}>
                    <div>
                      <ShieldAlert size={17} />
                      <strong>{f.title}</strong>
                      <span>{f.severity}</span>
                    </div>
                    <p>{f.evidence}</p>
                    <small>
                      {f.mode === 'monitor'
                        ? 'Recorded in monitor mode'
                        : 'Enforced by policy'}{' '}
                      · {f.rule}
                    </small>
                  </div>
                ))
              ) : (
                <div className="finding clear">
                  <Check size={18} />
                  <p>
                    The request passed authentication, applicable endpoint
                    checks, and its rate budget.
                  </p>
                </div>
              )}
              <p className="footnote">
                Stored evidence contains rule descriptions and safe metadata,
                never bearer tokens or raw payloads.
              </p>
              <div className="drawer-actions">
                <button
                  className="button secondary"
                  disabled={!!busy || !!selected.reviewed}
                  onClick={() => void review(selected)}
                >
                  <Check size={16} />
                  {selected.reviewed ? 'Reviewed' : 'Mark reviewed'}
                </button>
                {selected.scenario && (
                  <button
                    className="button primary"
                    disabled={!!busy}
                    onClick={() => {
                      const s = selected.scenario as ScenarioId;
                      setSelected(null);
                      setTab('Playground');
                      void execute(s).catch(() => {});
                    }}
                  >
                    <RotateCcw size={16} />
                    Replay scenario
                  </button>
                )}
              </div>
              <button
                className="text-button"
                onClick={() => {
                  setSelected(null);
                  setTab('Policies');
                }}
              >
                Review control policies <ArrowRight size={15} />
              </button>
            </div>
          </dialog>
        </div>
      )}
      {editing && (
        <div className="modal-backdrop">
          <dialog
            open
            className="policy-modal"
            aria-modal="true"
            aria-labelledby="policy-modal-title"
          >
            <div className="panel-title">
              <h2 id="policy-modal-title">
                Configure {RULES.find((r) => r.id === editing)?.title}
              </h2>
              <button
                className="icon-button"
                onClick={() => setEditing(null)}
                aria-label="Close policy settings"
              >
                <X size={20} />
              </button>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void savePolicy();
              }}
            >
              <label>
                Enforcement mode
                <select
                  autoFocus
                  value={mode}
                  onChange={(e) => setMode(e.target.value as Mode)}
                >
                  <option value="block">
                    Enforce — block or filter matches
                  </option>
                  <option value="monitor">
                    Monitor — record and allow matches
                  </option>
                </select>
              </label>
              {mode === 'monitor' && (
                <p className="mode-warning">
                  Matching{' '}
                  {editing === 'exposure'
                    ? 'synthetic response fields'
                    : 'requests'}{' '}
                  will pass through. Authentication and ownership remain
                  enforced.
                </p>
              )}
              <label>
                Reason for this change
                <textarea
                  required
                  minLength={5}
                  maxLength={300}
                  placeholder="Explain the adjustment for the audit trail…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </label>
              <div className="modal-actions">
                <button
                  className="button secondary"
                  type="button"
                  onClick={() => setEditing(null)}
                >
                  Cancel
                </button>
                <button
                  className="button primary"
                  disabled={!!busy || reason.trim().length < 5}
                >
                  Save policy
                </button>
              </div>
            </form>
          </dialog>
        </div>
      )}
    </div>
  );
}
function TrafficChart({ state }: { state: State | null }) {
  const now = Math.floor((state?.now ?? 0) / 60000),
    buckets = Array.from(
      { length: 30 },
      (_, i) =>
        state?.series.find((s) => s.minute === now - 29 + i) ?? {
          minute: now - 29 + i,
          total: 0,
          blocked: 0,
        },
    );
  const max = Math.max(4, ...buckets.map((b) => b.total)),
    points = (key: 'total' | 'blocked') =>
      buckets
        .map((b, i) => `${36 + i * 20},${156 - (b[key] / max) * 124}`)
        .join(' ');
  return (
    <div className="traffic-chart">
      {/* Inline SVG has an accessible name; replacing it with img would lose the dynamic chart. */}
      {/* oxlint-disable-next-line jsx-a11y/prefer-tag-over-role */}
      <svg
        viewBox="0 0 652 196"

        aria-label="Requests per minute over the past 30 minutes"
      >
        <defs>
          <linearGradient id="area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#c4f46b" stopOpacity=".17" />
            <stop offset="100%" stopColor="#c4f46b" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 1, 2, 3, 4].map((i) => (
          <g key={i}>
            <line
              x1="36"
              x2="624"
              y1={32 + i * 31}
              y2={32 + i * 31}
              stroke="#252c38"
              strokeDasharray="3 5"
            />
            <text x="7" y={36 + i * 31}>
              {Math.round(max * (1 - i / 4))}
            </text>
          </g>
        ))}
        <polygon
          points={`36,156 ${points('total')} 616,156`}
          fill="url(#area)"
        />
        <polyline
          points={points('total')}
          fill="none"
          stroke="#c4f46b"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        <polyline
          points={points('blocked')}
          fill="none"
          stroke="#f17c81"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        {[0, 10, 20, 29].map((i) => (
          <text
            key={i}
            x={36 + i * 20}
            y="184"
            textAnchor={i === 29 ? 'end' : 'start'}
          >
            {i === 29 ? 'Now' : `${29 - i}m ago`}
          </text>
        ))}
      </svg>
    </div>
  );
}
