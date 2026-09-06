import {
  verifyToken,
  suspiciousInput,
  validateOrder,
  filterProfile,
  type Finding,
  type RuleId,
} from './security';
import {
  policies,
  secret,
  consumeRate,
  saveEvent,
  type EventRecord,
} from './store';
import { ORDERS, profile, search } from './demo-api';
export function json(
  body: unknown,
  status = 200,
  extra: Record<string, string> = {},
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extra,
    },
  });
}
export async function readJson(
  request: Request,
  max = 16384,
): Promise<unknown> {
  if (
    !request.headers
      .get('content-type')
      ?.toLowerCase()
      .startsWith('application/json')
  )
    throw new Error('Content-Type must be application/json.');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('A JSON body is required.');
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > max) {
        await reader.cancel();
        throw new Error('Request exceeds the 16 KB body limit.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined));
  } catch {
    throw new Error('Body must contain valid UTF-8 JSON.');
  }
}
export async function gateway(
  request: Request,
  context: { scenario?: string; namespace?: string } = {},
) {
  const start = Date.now();
  const id = crypto.randomUUID();
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/gateway/, '');
  const modes = await policies();
  const findings: Finding[] = [];
  let identity = 'anonymous';
  let endpoint = 'unregistered';
  const add = (
    rule: RuleId,
    title: string,
    evidence: string,
    severity: 'high' | 'medium' = 'high',
  ) => findings.push({ rule, title, evidence, severity, mode: modes[rule] });
  const finish = async (
    body: unknown,
    status: number,
    action: string,
    headers: Record<string, string> = {},
  ) => {
    const event: EventRecord = {
      id,
      at: start,
      method: [
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'HEAD',
        'OPTIONS',
      ].includes(request.method)
        ? request.method
        : 'OTHER',
      endpoint,
      identity,
      action,
      status,
      duration: Date.now() - start,
      findings,
      scenario: context.scenario ?? null,
      reviewed: 0,
    };
    await saveEvent(event);
    return json(body, status, {
      'X-Sentinel-Request-Id': id,
      'X-Sentinel-Action': action,
      ...headers,
    });
  };
  const orderMatch = /^\/orders\/(ord_[0-9]{4})$/.exec(path);
  if (request.method === 'GET' && orderMatch) endpoint = '/orders/:id';
  else if (request.method === 'GET' && ['/profile', '/search'].includes(path))
    endpoint = path;
  else if (request.method === 'POST' && path === '/orders') endpoint = path;
  else {
    add(
      'schema',
      'Unregistered endpoint',
      'The route or HTTP method is not in the gateway inventory.',
      'medium',
    );
    return finish({ error: 'Route not registered.' }, 404, 'blocked');
  }
  try {
    identity = await verifyToken(
      request.headers.get('authorization'),
      await secret(),
    );
  } catch (error) {
    add('authentication', 'Authentication rejected', (error as Error).message);
    return finish({ error: 'Authentication required.' }, 401, 'blocked', {
      'WWW-Authenticate': 'Bearer',
    });
  }
  const rate = await consumeRate(identity, context.namespace ?? 'live');
  if (rate.count > 10) {
    add(
      'rate_limit',
      'Request budget exceeded',
      `Identity exceeded 10 requests in a fixed 60-second window (request ${rate.count}).`,
      'medium',
    );
    if (modes.rate_limit === 'block')
      return finish(
        { error: 'Request limit exceeded.', retryAfter: rate.retryAfter },
        429,
        'blocked',
        { 'Retry-After': String(rate.retryAfter) },
      );
  }
  if (url.search.length > 2048) {
    add(
      'schema',
      'Query too large',
      'Query string exceeds 2,048 characters.',
      'medium',
    );
    return finish({ error: 'Query too large.' }, 400, 'blocked');
  }
  const keys = [...url.searchParams.keys()];
  if (
    keys.some((k) => endpoint !== '/search' || k !== 'q') ||
    url.searchParams.getAll('q').length > 1
  ) {
    add(
      'schema',
      'Unexpected query parameters',
      'Unknown or duplicate query parameters were rejected.',
      'medium',
    );
    return finish({ error: 'Invalid query parameters.' }, 400, 'blocked');
  }
  let body: Record<string, unknown> = {};
  if (request.method === 'POST') {
    try {
      const parsed = await readJson(request);
      const invalid = validateOrder(parsed);
      if (invalid) throw new Error(invalid);
      body = parsed as Record<string, unknown>;
    } catch (error) {
      add(
        'schema',
        'Request contract violated',
        (error as Error).message,
        'medium',
      );
      return finish({ error: 'Invalid request body.' }, 400, 'blocked');
    }
  }
  const query = url.searchParams.get('q') ?? '';
  if (endpoint === '/search' && query.length > 200) {
    add(
      'schema',
      'Search query too long',
      'q must contain at most 200 characters.',
      'medium',
    );
    return finish({ error: 'Invalid search query.' }, 400, 'blocked');
  }
  const signal = suspiciousInput(
    endpoint === '/search'
      ? query
      : typeof body.item === 'string'
        ? body.item
        : '',
  );
  if (signal) {
    add('injection', 'Suspicious input pattern', signal);
    if (modes.injection === 'block')
      return finish(
        { error: 'Input rejected by security policy.' },
        403,
        'blocked',
      );
  }
  let response: Record<string, unknown>;
  if (orderMatch) {
    const order = ORDERS[orderMatch[1]];
    if (!order)
      return finish(
        { error: 'Order not found.' },
        404,
        findings.length ? 'monitored' : 'allowed',
      );
    if (order.owner !== identity) {
      add(
        'ownership',
        'Cross-user object access',
        'Verified token subject does not own the requested order.',
      );
      return finish({ error: 'Access denied.' }, 403, 'blocked');
    }
    const { owner: _, ...publicOrder } = order;
    response = publicOrder;
  } else if (endpoint === '/profile') {
    response = profile(identity);
    const filtered = filterProfile(response);
    if (filtered.removed.length) {
      add(
        'exposure',
        'Unapproved response fields',
        `Properties outside the allowlist: ${filtered.removed.join(', ')}. Values omitted.`,
      );
      if (modes.exposure === 'block')
        return finish(filtered.body, 200, 'filtered');
    }
  } else if (endpoint === '/search') response = search(query);
  else response = { accepted: true, item: body.item, quantity: body.quantity };
  return finish(response, 200, findings.length ? 'monitored' : 'allowed');
}
