# Threat model and honest limits

## Covered adversary actions

- Calling a configured demo route with missing, malformed, expired, forged, or
  wrong-claim tokens.
- Using one valid demo identity to access another identity's order.
- Submitting unknown properties, invalid data types, malformed JSON, excessive
  body sizes, duplicate query keys, and selected SQL/script patterns.
- Sending concurrent requests beyond the authenticated identity budget.
- Receiving properties outside the profile response allowlist.

## Trust boundaries

The hosted operator console relies on Sites owner-only access. A same-origin
Origin check and cross-site Fetch Metadata rejection protect console mutations
against browser CSRF; they are not operator authentication. All console users
are trusted to issue Alice/Bob demo tokens and change editable policies. Local
deployment is for one trusted operator on loopback. Never expose it publicly
without an independent authentication layer.

The synthetic identity issuer and upstream are deliberately limited to this
lab. Their tokens and identifiers must never be used for real applications.
Database access, local machine compromise, and a compromised authorized operator
are outside this prototype's protection boundary.

## Detection limits and false positives

Injection matching is a heuristic. It neither proves exploitability nor detects
all encodings, parser differences, or evasions. Normal text can match suspicious
patterns; monitor mode and explicit evidence support tuning. Production backends
still need parameterized SQL, contextual output encoding, and safe command APIs.

Object authorization is enforced for this known order model. A generic gateway
cannot infer ownership or business permissions reliably from arbitrary traffic.
The response allowlist is configured for the synthetic profile; it is not a
generic PII classifier. All non-allowlisted profile fields are removed, including
unknown nested objects; general nested-schema filtering is not implemented.

The limiter counts verified identities; there is no implemented per-IP or
pre-authentication DDoS limiter. Invalid authentication attempts do not consume
that budget. Add edge protections for internet exposure. Fixed minute windows
permit boundary bursts. Database storage and latency have not been load tested.

## Operational limits

- Single private workspace, no multi-tenant isolation or administrator roles.
- In-process synthetic upstream, not an external reverse proxy or scanner.
- No automatic endpoint discovery, statistical anomaly model, alert delivery,
  threat-intelligence feed, or global bot detection.
- Inline database writes favor audit completeness over peak throughput.
- No automatic event retention; configure retention before extended operation.
- Evaluation duration excludes the final event write and HTTP transport.
- Policy reasons can contain operator-entered sensitive text. Do not paste secrets.
- Monitor mode for data exposure deliberately returns synthetic internal fields.
- Prototype signing key resides in the server-side database; production needs
  managed secret storage, controlled rotation, and a reviewed token library.

## Safe testing

The playground accepts predefined scenario names, not arbitrary target URLs.
All sample data is synthetic. Integration tests mutate local demo policies and
restore their previous modes. Do not point test tooling at another system
without its owner's authorization.
