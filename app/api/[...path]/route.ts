import { gateway, json, readJson } from '../../../lib/gateway';
import {
  dashboard,
  database,
  initialize,
  secret,
  updatePolicy,
  consumeRate,
} from '../../../lib/store';
import {
  RULES,
  SCENARIOS,
  ENDPOINTS,
  issueToken,
  type Mode,
  type RuleId,
  type ScenarioId,
} from '../../../lib/security';
import { runScenario } from '../../../lib/scenarios';

// The hosted control plane is behind Sites owner-only access. Local use binds
// to loopback. Mutations require same-origin JSON; no permissive CORS is emitted.
async function handle(request: Request) {
  const url = new URL(request.url);
  try {
    if (url.pathname.startsWith('/api/gateway/')) return await gateway(request);
    if (!url.pathname.startsWith('/api/console/'))
      return json({ error: 'Not found.' }, 404);
    if (request.headers.get('sec-fetch-site') === 'cross-site')
      return json({ error: 'Cross-site access denied.' }, 403);
    if (request.method === 'GET' && url.pathname === '/api/console/state')
      return json({
        ...(await dashboard()),
        inventory: ENDPOINTS,
        rules: RULES,
        scenarios: SCENARIOS,
      });
    if (request.method !== 'POST')
      return json({ error: 'Method not allowed.' }, 405, { Allow: 'POST' });
    if (request.headers.get('origin') !== url.origin)
      return json({ error: 'Same-origin requests are required.' }, 403);
    let body: Record<string, unknown>;
    try {
      const value = await readJson(request);
      if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error();
      body = value as Record<string, unknown>;
    } catch {
      return json(
        { error: 'A valid JSON object under 16 KB is required.' },
        400,
      );
    }
    await initialize();
    if (url.pathname === '/api/console/policy') {
      const rule = RULES.find((r) => r.id === body.id);
      if (
        !rule ||
        rule.locked ||
        !['block', 'monitor'].includes(String(body.mode)) ||
        typeof body.reason !== 'string' ||
        body.reason.trim().length < 5 ||
        body.reason.length > 300
      )
        return json(
          {
            error:
              'Choose an editable rule, a valid mode, and a reason of 5–300 characters.',
          },
          400,
        );
      await updatePolicy(
        rule.id as RuleId,
        body.mode as Mode,
        body.reason.trim(),
      );
      return json({ ok: true });
    }
    if (url.pathname === '/api/console/review') {
      if (typeof body.id !== 'string' || !/^[0-9a-f-]{36}$/.test(body.id))
        return json({ error: 'Invalid event identifier.' }, 400);
      const found = await database()
        .prepare('SELECT id FROM events WHERE id = ?')
        .bind(body.id)
        .first();
      if (!found) return json({ error: 'Event not found.' }, 404);
      await database().batch([
        database()
          .prepare('UPDATE events SET reviewed = 1 WHERE id = ?')
          .bind(body.id),
        database()
          .prepare(
            'INSERT INTO audit (id, at, rule, mode, reason) VALUES (?, ?, ?, ?, ?)',
          )
          .bind(
            crypto.randomUUID(),
            Date.now(),
            'event_review',
            'reviewed',
            `Reviewed event ${body.id}`,
          ),
      ]);
      return json({ ok: true });
    }
    if (url.pathname === '/api/console/token') {
      if (!['alice', 'bob'].includes(String(body.subject)))
        return json({ error: 'Unknown demo subject.' }, 400);
      return json({
        token: await issueToken(await secret(), body.subject as string),
        expiresIn: 300,
      });
    }
    if (url.pathname === '/api/console/run') {
      if (!SCENARIOS.some((s) => s.id === body.scenario))
        return json({ error: 'Unknown scenario.' }, 400);
      const rate = await consumeRate('operator', 'scenario-control');
      if (rate.count > 30)
        return json(
          { error: 'Please wait before running more scenarios.' },
          429,
          { 'Retry-After': String(rate.retryAfter) },
        );
      return json(await runScenario(body.scenario as ScenarioId, url.origin));
    }
    return json({ error: 'Not found.' }, 404);
  } catch (error) {
    console.error(
      'Sentinel request failed:',
      error instanceof Error ? error.name : 'UnknownError',
    );
    return json(
      {
        error:
          'Security service unavailable. The request was not allowed to proceed.',
      },
      503,
    );
  }
}
export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const OPTIONS = handle;
