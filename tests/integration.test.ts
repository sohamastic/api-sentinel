import test from 'node:test';
import assert from 'node:assert/strict';
const origin = process.env.SENTINEL_TEST_URL ?? 'http://localhost:3000';
async function post(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return fetch(`${origin}/api/console/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin, ...headers },
    body: JSON.stringify(body),
  });
}
async function run(scenario: string) {
  const response = await post('run', { scenario });
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as {
    responses: {
      status: number;
      action: string;
      body: Record<string, unknown>;
      requestId: string;
    }[];
  };
}
void test('live gateway and control plane', async (t) => {
  const initialResponse = await fetch(`${origin}/api/console/state`);
  assert.equal(
    initialResponse.status,
    200,
    'Start the app and run database migrations first.',
  );
  const initial = (await initialResponse.json()) as {
    policies: Record<string, string>;
  };
  for (const id of ['injection', 'rate_limit', 'exposure'])
    assert.equal(
      (
        await post('policy', {
          id,
          mode: 'block',
          reason: 'Integration test: establish enforcement baseline.',
        })
      ).status,
      200,
    );
  try {
    await t.test('nine scenarios enforce the expected outcomes', async () => {
      const cases: [string, number, string][] = [
        ['legitimate', 200, 'allowed'],
        ['missing_auth', 401, 'blocked'],
        ['expired_token', 401, 'blocked'],
        ['tampered_token', 401, 'blocked'],
        ['ownership', 403, 'blocked'],
        ['injection', 403, 'blocked'],
        ['schema', 400, 'blocked'],
        ['exposure', 200, 'filtered'],
      ];
      for (const [id, status, action] of cases) {
        const result = await run(id);
        assert.equal(result.responses[0].status, status, id);
        assert.equal(result.responses[0].action, action, id);
        if (id === 'exposure')
          assert.deepEqual(Object.keys(result.responses[0].body), [
            'id',
            'name',
            'email',
          ]);
      }
    });
    await t.test(
      '14 concurrent requests admit exactly 10 and limit 4',
      async () => {
        const result = await run('burst');
        assert.equal(
          result.responses.filter((r) => r.status === 200).length,
          10,
        );
        assert.equal(
          result.responses.filter((r) => r.status === 429).length,
          4,
        );
      },
    );
    await t.test(
      'injection monitor allows the request but records the finding',
      async () => {
        assert.equal(
          (
            await post('policy', {
              id: 'injection',
              mode: 'monitor',
              reason: 'Integration test: measure false positives.',
            })
          ).status,
          200,
        );
        const result = await run('injection');
        assert.equal(result.responses[0].status, 200);
        assert.equal(result.responses[0].action, 'monitored');
      },
    );
    await t.test(
      'exposure monitor returns only synthetic internal values',
      async () => {
        await post('policy', {
          id: 'exposure',
          mode: 'monitor',
          reason: 'Integration test: inspect synthetic response contract.',
        });
        const result = await run('exposure');
        assert.equal(result.responses[0].action, 'monitored');
        assert.equal(
          result.responses[0].body.passwordHash,
          'SYNTHETIC_NOT_A_REAL_HASH',
        );
      },
    );
    await t.test(
      'rate monitor allows all 14 and records 4 budget violations',
      async () => {
        await post('policy', {
          id: 'rate_limit',
          mode: 'monitor',
          reason: 'Integration test: inspect burst policy.',
        });
        const result = await run('burst');
        assert.equal(
          result.responses.filter((r) => r.status === 200).length,
          14,
        );
        assert.equal(
          result.responses.filter((r) => r.action === 'monitored').length,
          4,
        );
      },
    );
    await t.test('mandatory controls cannot be disabled', async () => {
      for (const id of ['authentication', 'ownership', 'schema'])
        assert.equal(
          (
            await post('policy', {
              id,
              mode: 'monitor',
              reason: 'This change must be rejected.',
            })
          ).status,
          400,
        );
    });
    await t.test(
      'cross-origin and missing-origin policy writes are rejected',
      async () => {
        const body = {
          id: 'injection',
          mode: 'monitor',
          reason: 'This change must be rejected.',
        };
        assert.equal(
          (await post('policy', body, { Origin: 'https://untrusted.example' }))
            .status,
          403,
        );
        assert.equal(
          (
            await fetch(`${origin}/api/console/policy`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body),
            })
          ).status,
          403,
        );
      },
    );
    await t.test(
      'unknown scenarios and missing audit reason are rejected',
      async () => {
        assert.equal(
          (await post('run', { scenario: 'arbitrary_url' })).status,
          400,
        );
        assert.equal(
          (await post('policy', { id: 'injection', mode: 'block', reason: '' }))
            .status,
          400,
        );
      },
    );
    await t.test(
      'direct HTTP calls enforce both object ownership and input contracts',
      async () => {
        const minted = await post('token', { subject: 'bob' });
        const { token } = (await minted.json()) as { token: string };
        const headers = { Authorization: `Bearer ${token}` };
        assert.equal(
          (await fetch(`${origin}/api/gateway/orders/ord_1002`, { headers }))
            .status,
          200,
        );
        assert.equal(
          (await fetch(`${origin}/api/gateway/orders/ord_1001`, { headers }))
            .status,
          403,
        );
        assert.equal(
          (await fetch(`${origin}/api/gateway/unknown`, { headers })).status,
          404,
        );
        assert.equal(
          (await fetch(`${origin}/api/gateway/search?q=a&q=b`, { headers }))
            .status,
          400,
        );
        assert.equal(
          (
            await fetch(`${origin}/api/gateway/orders`, {
              method: 'POST',
              headers: { ...headers, 'Content-Type': 'application/json' },
              body: '{"broken"',
            })
          ).status,
          400,
        );
        assert.equal(
          (
            await fetch(`${origin}/api/gateway/orders`, {
              method: 'POST',
              headers: { ...headers, 'Content-Type': 'application/json' },
              body: JSON.stringify({ item: 'x'.repeat(18000), quantity: 1 }),
            })
          ).status,
          400,
        );
      },
    );
    await t.test(
      'stored decisions omit token, request payload and sensitive response values',
      async () => {
        const response = await fetch(`${origin}/api/console/state`);
        const state = (await response.json()) as {
          events: { id: string; findings: unknown[]; reviewed: number }[];
        };
        const events = JSON.stringify(state.events);
        for (const value of [
          'Bearer ',
          'SYNTHETIC_NOT_A_REAL_HASH',
          'SYNTHETIC_NOT_A_REAL_TOKEN',
          'UNION SELECT password',
          'alice@example.test',
        ])
          assert.ok(!events.includes(value), value);
        const event = state.events.find((e) => e.findings.length)!;
        assert.equal((await post('review', { id: event.id })).status, 200);
        const reread = (await (
          await fetch(`${origin}/api/console/state`)
        ).json()) as typeof state;
        assert.equal(reread.events.find((e) => e.id === event.id)?.reviewed, 1);
      },
    );
  } finally {
    for (const id of ['injection', 'rate_limit', 'exposure'])
      await post('policy', {
        id,
        mode: initial.policies[id],
        reason: 'Integration test: restore original policy mode.',
      });
  }
});
