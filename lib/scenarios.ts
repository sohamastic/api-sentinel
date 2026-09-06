import { SCENARIOS, issueToken, type ScenarioId } from './security';
import { secret, database } from './store';
import { gateway } from './gateway';
export async function runScenario(id: ScenarioId, origin: string) {
  const scenario = SCENARIOS.find((s) => s.id === id);
  if (!scenario) throw new Error('Unknown scenario.');
  let token = await issueToken(
    await secret(),
    'alice',
    id === 'expired_token' ? -60 : 300,
  );
  if (id === 'tampered_token') {
    const parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    token = parts.join('.');
  }
  const namespace = `demo:${crypto.randomUUID()}`;
  let path: string = scenario.path;
  if (id === 'injection')
    path += '?q=' + encodeURIComponent("' UNION SELECT password FROM users --");
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (id !== 'missing_auth') headers.Authorization = `Bearer ${token}`;
  const count = id === 'burst' ? 14 : 1;
  const responses = await Promise.all(
    Array.from({ length: count }, async () => {
      const request = new Request(`${origin}/api/gateway${path}`, {
        method: scenario.method,
        headers,
        ...(scenario.method === 'POST'
          ? {
              body: JSON.stringify({
                item: 'Keyboard',
                quantity: 1,
                role: 'admin',
              }),
            }
          : {}),
      });
      const response = await gateway(request, { scenario: id, namespace });
      return {
        status: response.status,
        action: response.headers.get('X-Sentinel-Action'),
        requestId: response.headers.get('X-Sentinel-Request-Id'),
        body: await response.json(),
        retryAfter: response.headers.get('Retry-After'),
      };
    }),
  );
  await database()
    .prepare('DELETE FROM rate_buckets WHERE key = ?')
    .bind(`${namespace}:alice`)
    .run();
  return {
    scenario: id,
    title: scenario.title,
    responses,
    summary: {
      total: responses.length,
      blocked: responses.filter((r) => r.action === 'blocked').length,
      filtered: responses.filter((r) => r.action === 'filtered').length,
    },
  };
}
