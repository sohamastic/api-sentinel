/** Pure security primitives: no runtime bindings, network calls, or persistence. */
export type Mode = 'block' | 'monitor';
export type RuleId =
  | 'authentication'
  | 'ownership'
  | 'schema'
  | 'injection'
  | 'rate_limit'
  | 'exposure';
export type Finding = {
  rule: RuleId;
  title: string;
  evidence: string;
  severity: 'high' | 'medium';
  mode: Mode;
};
export const RULES = [
  {
    id: 'authentication',
    title: 'Token verification',
    category: 'API2 · Authentication',
    description:
      'Verify HS256 signature, issuer, audience, subject, issue time, and expiry.',
    locked: true,
  },
  {
    id: 'ownership',
    title: 'Object ownership',
    category: 'API1 · Object authorization',
    description:
      'Compare the verified subject with the server-owned order record.',
    locked: true,
  },
  {
    id: 'schema',
    title: 'Request contract',
    category: 'Input validation',
    description:
      'Reject unknown fields, invalid types, oversized input, and unregistered routes.',
    locked: true,
  },
  {
    id: 'injection',
    title: 'Suspicious input',
    category: 'Injection heuristic',
    description:
      'Detect selected SQL injection and script patterns. Heuristics can produce false positives.',
    locked: false,
  },
  {
    id: 'rate_limit',
    title: 'Request burst control',
    category: 'API4 · Resource consumption',
    description:
      'Allow 10 requests per identity per fixed 60-second window across registered routes.',
    locked: false,
  },
  {
    id: 'exposure',
    title: 'Response field allowlist',
    category: 'API3 · Property authorization',
    description:
      'Strip unapproved profile properties. Monitor mode allows synthetic demo fields through.',
    locked: false,
  },
] as const;
export const ENDPOINTS = [
  {
    method: 'GET',
    path: '/orders/:id',
    description: 'Retrieve an owned order',
    rules: ['authentication', 'ownership', 'rate_limit'],
    fields: 'id, item, total, status',
  },
  {
    method: 'GET',
    path: '/profile',
    description: 'Retrieve the current profile',
    rules: ['authentication', 'exposure', 'rate_limit'],
    fields: 'id, name, email',
  },
  {
    method: 'GET',
    path: '/search',
    description: 'Search the product catalog',
    rules: ['authentication', 'schema', 'injection', 'rate_limit'],
    fields: 'results',
  },
  {
    method: 'POST',
    path: '/orders',
    description: 'Validate a demo order',
    rules: ['authentication', 'schema', 'injection', 'rate_limit'],
    fields: 'accepted, item, quantity',
  },
];
export const SCENARIOS = [
  {
    id: 'legitimate',
    title: 'Legitimate request',
    description: 'Alice reads her own order.',
    method: 'GET',
    path: '/orders/ord_1001',
    expected: '200 · Allowed',
    group: 'Baseline',
  },
  {
    id: 'missing_auth',
    title: 'Missing authentication',
    description: 'A protected order is requested without a token.',
    method: 'GET',
    path: '/orders/ord_1001',
    expected: '401 · Blocked',
    group: 'Authentication',
  },
  {
    id: 'expired_token',
    title: 'Expired token',
    description: 'A correctly signed token has passed its expiry.',
    method: 'GET',
    path: '/orders/ord_1001',
    expected: '401 · Blocked',
    group: 'Authentication',
  },
  {
    id: 'tampered_token',
    title: 'Tampered identity',
    description: 'A token signature is changed after signing.',
    method: 'GET',
    path: '/orders/ord_1001',
    expected: '401 · Blocked',
    group: 'Authentication',
  },
  {
    id: 'ownership',
    title: 'Cross-user access',
    description: 'Alice attempts to read Bob’s order.',
    method: 'GET',
    path: '/orders/ord_1002',
    expected: '403 · Blocked',
    group: 'Authorization',
  },
  {
    id: 'injection',
    title: 'SQL injection pattern',
    description: 'A search query contains a UNION SELECT pattern.',
    method: 'GET',
    path: '/search',
    expected: '403 · Blocked',
    group: 'Input validation',
  },
  {
    id: 'schema',
    title: 'Unexpected order fields',
    description: 'An order attempts to set an unauthorized role field.',
    method: 'POST',
    path: '/orders',
    expected: '400 · Blocked',
    group: 'Input validation',
  },
  {
    id: 'exposure',
    title: 'Excessive response data',
    description: 'A profile includes synthetic internal fields.',
    method: 'GET',
    path: '/profile',
    expected: '200 · Filtered',
    group: 'Data protection',
  },
  {
    id: 'burst',
    title: 'Request burst',
    description: 'Send 14 requests in one fresh rate-limit window.',
    method: 'GET',
    path: '/orders/ord_1001',
    expected: '10 allowed · 4 limited',
    group: 'Abuse prevention',
  },
] as const;
export type ScenarioId = (typeof SCENARIOS)[number]['id'];
const encode = (v: string | Uint8Array) =>
  btoa(typeof v === 'string' ? v : String.fromCharCode(...v))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
function decode(v: string) {
  return Uint8Array.from(
    atob(
      v.replace(/-/g, '+').replace(/_/g, '/') +
        '='.repeat((4 - (v.length % 4)) % 4),
    ),
    (c) => c.charCodeAt(0),
  );
}
async function signingKey(secret: string) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}
export async function issueToken(
  secret: string,
  subject = 'alice',
  ttl = 300,
  now = Date.now(),
) {
  const seconds = Math.floor(now / 1000);
  const data = `${encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${encode(JSON.stringify({ sub: subject, iss: 'sentinel-demo', aud: 'sentinel-gateway', iat: seconds, exp: seconds + ttl }))}`;
  const signature = await crypto.subtle.sign(
    'HMAC',
    await signingKey(secret),
    new TextEncoder().encode(data),
  );
  return `${data}.${encode(new Uint8Array(signature))}`;
}
export async function verifyToken(
  header: string | null,
  secret: string,
  now = Date.now(),
): Promise<string> {
  if (!header?.startsWith('Bearer ') || header.length > 2048)
    throw new Error('A valid bearer token is required.');
  try {
    const pieces = header.slice(7).split('.');
    if (
      pieces.length !== 3 ||
      pieces.some((v) => !v || !/^[A-Za-z0-9_-]+$/.test(v))
    )
      throw new Error();
    const [h, p, s] = pieces;
    const meta = JSON.parse(new TextDecoder().decode(decode(h)));
    if (meta.alg !== 'HS256' || meta.typ !== 'JWT') throw new Error();
    if (
      !(await crypto.subtle.verify(
        'HMAC',
        await signingKey(secret),
        decode(s),
        new TextEncoder().encode(`${h}.${p}`),
      ))
    )
      throw new Error();
    const payload = JSON.parse(new TextDecoder().decode(decode(p)));
    const seconds = Math.floor(now / 1000);
    if (
      !['alice', 'bob'].includes(payload.sub) ||
      payload.iss !== 'sentinel-demo' ||
      payload.aud !== 'sentinel-gateway' ||
      !Number.isInteger(payload.exp) ||
      !Number.isInteger(payload.iat) ||
      payload.exp <= seconds ||
      payload.iat > seconds + 5 ||
      payload.exp - payload.iat > 900
    )
      throw new Error();
    return payload.sub;
  } catch {
    throw new Error(
      'Token signature or required claims are invalid, or the token has expired.',
    );
  }
}
export function suspiciousInput(value: string): string | null {
  const normalized = value.normalize('NFKC').replace(/\/\*[\s\S]*?\*\//g, ' ');
  if (/\bunion\s+(?:all\s+)?select\b/i.test(normalized))
    return 'SQL UNION SELECT sequence detected; query values omitted.';
  if (
    /(?:'|")\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|['"][^'"]*['"]\s*=)/i.test(
      normalized,
    )
  )
    return 'SQL boolean-expression pattern detected; input values omitted.';
  if (/<\s*script\b|\bon(?:error|load)\s*=|javascript\s*:/i.test(normalized))
    return 'Executable script pattern detected; input values omitted.';
  return null;
}
export function validateOrder(body: unknown): string | null {
  if (!body || typeof body !== 'object' || Array.isArray(body))
    return 'Body must be a JSON object.';
  const item = body as Record<string, unknown>;
  if (Object.keys(item).some((k) => !['item', 'quantity'].includes(k)))
    return 'Request contains fields outside the order allowlist.';
  if (
    typeof item.item !== 'string' ||
    item.item.trim().length < 1 ||
    item.item.length > 120
  )
    return 'item must be a string between 1 and 120 characters.';
  if (
    !Number.isInteger(item.quantity) ||
    Number(item.quantity) < 1 ||
    Number(item.quantity) > 20
  )
    return 'quantity must be an integer between 1 and 20.';
  return null;
}
export function filterProfile(body: Record<string, unknown>) {
  const allowed = ['id', 'name', 'email'];
  return {
    body: Object.fromEntries(
      Object.entries(body).filter(([key]) => allowed.includes(key)),
    ),
    removed: Object.keys(body).filter((key) => !allowed.includes(key)),
  };
}
