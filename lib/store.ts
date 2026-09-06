import { env } from 'cloudflare:workers';
import { RULES, type Finding, type Mode, type RuleId } from './security';
export type EventRecord = {
  id: string;
  at: number;
  method: string;
  endpoint: string;
  identity: string;
  action: string;
  status: number;
  duration: number;
  findings: Finding[];
  scenario: string | null;
  reviewed: number;
};
export function database() {
  if (!env.DB) throw new Error('Security database unavailable.');
  return env.DB;
}
let initialization: Promise<void> | undefined;
export async function initialize() {
  if (!initialization)
    initialization = (async () => {
      const db = database();
      await db.batch(
        RULES.map((r) =>
          db
            .prepare(
              'INSERT INTO policies (id, mode, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING',
            )
            .bind(r.id, 'block', Date.now()),
        ),
      );
      const secret = Array.from(
        crypto.getRandomValues(new Uint8Array(32)),
        (b) => b.toString(16).padStart(2, '0'),
      ).join('');
      await db
        .prepare(
          'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING',
        )
        .bind('signing_secret', secret)
        .run();
    })().catch((error) => {
      initialization = undefined;
      throw error;
    });
  await initialization;
}
export async function secret() {
  await initialize();
  const row = await database()
    .prepare('SELECT value FROM settings WHERE key = ?')
    .bind('signing_secret')
    .first<{ value: string }>();
  if (!row) throw new Error('Signing key unavailable.');
  return row.value;
}
export async function policies(): Promise<Record<RuleId, Mode>> {
  await initialize();
  const rows = await database()
    .prepare('SELECT id, mode FROM policies')
    .all<{ id: RuleId; mode: Mode }>();
  const result = Object.fromEntries(
    rows.results.map((r) => [r.id, r.mode]),
  ) as Record<RuleId, Mode>;
  for (const rule of RULES) if (rule.locked) result[rule.id] = 'block';
  return result;
}
export async function consumeRate(
  identity: string,
  namespace = 'live',
  now = Date.now(),
) {
  const window = Math.floor(now / 60000);
  const key = `${namespace}:${identity}`;
  const row = await database()
    .prepare(`INSERT INTO rate_buckets (key, window, count) VALUES (?, ?, 1)
 ON CONFLICT(key) DO UPDATE SET window = excluded.window,
 count = CASE WHEN rate_buckets.window = excluded.window THEN rate_buckets.count + 1 ELSE 1 END RETURNING count`)
    .bind(key, window)
    .first<{ count: number }>();
  if (!row) throw new Error('Rate limiter unavailable.');
  return {
    count: row.count,
    retryAfter: Math.max(1, Math.ceil(((window + 1) * 60000 - now) / 1000)),
  };
}
export async function saveEvent(e: EventRecord) {
  await database()
    .prepare(
      'INSERT INTO events (id, at, method, endpoint, identity, action, status, duration, findings, scenario, reviewed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(
      e.id,
      e.at,
      e.method,
      e.endpoint,
      e.identity,
      e.action,
      e.status,
      e.duration,
      JSON.stringify(e.findings),
      e.scenario,
      e.reviewed,
    )
    .run();
}
export async function updatePolicy(id: RuleId, mode: Mode, reason: string) {
  const db = database();
  await db.batch([
    db
      .prepare('UPDATE policies SET mode = ?, updated_at = ? WHERE id = ?')
      .bind(mode, Date.now(), id),
    db
      .prepare(
        'INSERT INTO audit (id, at, rule, mode, reason) VALUES (?, ?, ?, ?, ?)',
      )
      .bind(crypto.randomUUID(), Date.now(), id, mode, reason),
  ]);
}
export async function dashboard() {
  await initialize();
  const db = database();
  const now = Date.now();
  const [recent, counts, byEndpoint, series, changes, modes] =
    await Promise.all([
      db
        .prepare('SELECT * FROM events ORDER BY at DESC, id DESC LIMIT 100')
        .all<Omit<EventRecord, 'findings'> & { findings: string }>(),
      db
        .prepare(
          `SELECT COUNT(*) AS total, COALESCE(SUM(action = 'blocked'),0) AS blocked, COALESCE(SUM(action = 'filtered'),0) AS filtered, COALESCE(SUM(action = 'monitored'),0) AS monitored, COALESCE(AVG(duration),0) AS latency FROM events`,
        )
        .first(),
      db
        .prepare(
          `SELECT endpoint, method, COUNT(*) AS requests, SUM(action = 'blocked') AS blocked, MAX(at) AS lastSeen FROM events GROUP BY endpoint, method`,
        )
        .all(),
      db
        .prepare(
          `SELECT CAST(at / 60000 AS INTEGER) AS minute, COUNT(*) AS total, SUM(action = 'blocked') AS blocked FROM events WHERE at >= ? GROUP BY minute ORDER BY minute`,
        )
        .bind(now - 29 * 60000)
        .all(),
      db.prepare('SELECT * FROM audit ORDER BY at DESC LIMIT 30').all(),
      policies(),
    ]);
  return {
    events: recent.results.map((e) => ({
      ...e,
      findings: JSON.parse(e.findings),
    })),
    counts,
    endpoints: byEndpoint.results,
    series: series.results,
    audit: changes.results,
    policies: modes,
    now,
  };
}
