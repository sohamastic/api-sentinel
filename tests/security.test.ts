import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  issueToken,
  verifyToken,
  suspiciousInput,
  validateOrder,
  filterProfile,
} from '../lib/security.ts';
const secret = 'test-only-key-with-at-least-thirty-two-characters';
const now = 1800000000000;
const signed = (claims: Record<string, unknown>, alg = 'HS256') => {
  const h = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString(
      'base64url',
    ),
    p = Buffer.from(
      JSON.stringify({
        sub: 'alice',
        iss: 'sentinel-demo',
        aud: 'sentinel-gateway',
        iat: now / 1000,
        exp: now / 1000 + 300,
        ...claims,
      }),
    ).toString('base64url');
  return `Bearer ${h}.${p}.${createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')}`;
};
void test('valid tokens identify both demo users', async () => {
  for (const user of ['alice', 'bob'])
    assert.equal(
      await verifyToken(
        `Bearer ${await issueToken(secret, user, 300, now)}`,
        secret,
        now,
      ),
      user,
    );
});
void test('missing token is rejected', async () => {
  await assert.rejects(verifyToken(null, secret, now));
});
void test('tampered signature is rejected', async () => {
  const token = await issueToken(secret, 'alice', 300, now);
  const [h, p, s] = token.split('.');
  await assert.rejects(
    verifyToken(
      `Bearer ${h}.${p}.${s[0] === 'A' ? 'B' : 'A'}${s.slice(1)}`,
      secret,
      now,
    ),
  );
});
void test('expiry is enforced at exact boundary', async () => {
  const token = await issueToken(secret, 'alice', 300, now);
  await assert.rejects(verifyToken(`Bearer ${token}`, secret, now + 300000));
});
void test('wrong signing key is rejected', async () => {
  await assert.rejects(
    verifyToken(
      `Bearer ${await issueToken('wrong-key', 'alice', 300, now)}`,
      secret,
      now,
    ),
  );
});
for (const [name, claims] of Object.entries({
  issuer: { iss: 'attacker' },
  audience: { aud: 'other' },
  subject: { sub: 'admin' },
  future: { iat: now / 1000 + 60 },
  missingExpiry: { exp: null },
  stringExpiry: { exp: String(now / 1000 + 300) },
  longLifetime: { exp: now / 1000 + 901 },
}))
  void test(`rejects invalid ${name} claim`, async () => {
    await assert.rejects(verifyToken(signed(claims), secret, now));
  });
void test('algorithm confusion is rejected', async () => {
  await assert.rejects(verifyToken(signed({}, 'none'), secret, now));
});
void test('oversized and malformed bearer strings fail closed', async () => {
  for (const value of [
    'Bearer a.b',
    'Bearer ' + 'x'.repeat(3000),
    'Basic abc',
    'Bearer ....',
  ])
    await assert.rejects(verifyToken(value, secret, now));
});
void test('detects SQL patterns including inline comments', () => {
  for (const value of [
    "' UNION SELECT password FROM users --",
    'UNION/**/SELECT',
    'ＵＮＩＯＮ SELECT',
    "' or 1=1 --",
  ])
    assert.ok(suspiciousInput(value));
});
void test('detects selected executable script patterns', () => {
  for (const value of [
    '<script>alert(1)</script>',
    '<img onerror=alert(1)>',
    'javascript:alert(1)',
  ])
    assert.ok(suspiciousInput(value));
});
void test('ordinary search words and apostrophes are allowed', () => {
  for (const value of [
    'Keyboard',
    'O’Reilly books',
    "O'Reilly",
    'select a union membership',
  ])
    assert.equal(suspiciousInput(value), null);
});
void test('valid order contract accepts boundary quantities', () => {
  for (const quantity of [1, 20])
    assert.equal(validateOrder({ item: 'Keyboard', quantity }), null);
});
void test('rejects mass assignment, invalid quantities and unexpected shapes', () => {
  for (const body of [
    { item: 'Keyboard', quantity: 1, role: 'admin' },
    { item: 'Keyboard', quantity: '1' },
    { item: 'Keyboard', quantity: 1.5 },
    { item: 'Keyboard', quantity: 0 },
    { item: 'Keyboard', quantity: 21 },
    { item: ' ', quantity: 1 },
    [],
    null,
  ])
    assert.ok(validateOrder(body));
});
void test('response allowlist strips unknown and nested properties without mutation', () => {
  const source = {
    id: 'alice',
    name: 'Alice',
    email: 'alice@example.test',
    passwordHash: 'sensitive',
    nested: { secret: 'sensitive' },
  };
  const result = filterProfile(source);
  assert.deepEqual(Object.keys(result.body), ['id', 'name', 'email']);
  assert.deepEqual(result.removed, ['passwordHash', 'nested']);
  assert.equal(source.passwordHash, 'sensitive');
});
