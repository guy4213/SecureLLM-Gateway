# SecureLLM Gateway

A production-grade secure reverse proxy that sits between enterprise applications and LLM providers (OpenAI). Every inbound request passes through a seven-layer security and observability pipeline before the prompt is forwarded to the upstream model.

---

## Quick start

```bash
# 1. Copy and fill in the environment file
cp .env.example .env

# 2. Generate a PII encryption key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# → paste the output as PII_ENC_KEY in .env

# 3. Start the full stack (API gateway + MongoDB + Redis)
docker-compose up --build
```

The gateway listens on **port 3000** by default.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | HTTP port (default `3000`) |
| `NODE_ENV` | No | `production` \| `development` \| `test` |
| `MONGO_URI` | Yes | MongoDB connection string (e.g. `mongodb://admin:password@mongo:27017/securellm?authSource=admin`) |
| `REDIS_URI` | Yes | Redis connection string (e.g. `redis://redis:6379`) |
| `OPENAI_API_KEY` | Yes* | OpenAI key (`sk-...`). If absent the gateway starts but `/v1/chat` returns **503** and `/healthz` reports `missing_key` |
| `PII_ENC_KEY` | Yes* | 64 hex chars (32-byte AES key) for encrypting PII maps at rest in MongoDB. Generate: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. If absent, redaction works but mappings cannot be recovered at audit time. |
| `RATE_LIMIT_WINDOW_MS` | No | Sliding window duration in ms (default `60000`) |
| `RATE_LIMIT_MAX_REQUESTS` | No | Global max requests per window per API key (default `30`). Individual keys can override this via `ApiKey.rateLimitPerMinute` in MongoDB. |
| `LLM_REQUEST_TIMEOUT_MS` | No | Hard timeout for upstream OpenAI calls in ms. Range: 1000–120000 (default `30000`). Requests that exceed this receive `503`. |
| `LLM_CACHE_TTL_SECONDS` | No | Per-tenant response cache TTL in seconds. Set to `0` to disable caching entirely (default `300`). |
| `MAX_TOKENS_CAP` | No | Server-side ceiling on `max_tokens`. Requests exceeding this return `400` with a `MAX_TOKENS_EXCEEDED` threat flag in the audit log (default `2048`). |
| `MONGO_ROOT_USER` | No | MongoDB root username used by docker-compose (default `admin`) |
| `MONGO_ROOT_PASSWORD` | No | MongoDB root password used by docker-compose (default `password`) |

---

## Security & observability pipeline

Each `POST /v1/chat` request traverses these layers **in strict order**:

```
Request
  │
  ├─ [correlation-id]     UUID per request → X-Request-ID response header
  ├─ [body parser]        1 MB hard ceiling → 413 if exceeded
  ├─ [security headers]   X-Content-Type-Options, X-Frame-Options, CSP, no X-Powered-By
  │
  ▼ POST /v1/chat
  ├─ [1] AuditLogger       SecurityContext + res.on('finish') hook
  ├─ [2] Authenticate      x-api-key → SHA-256 → MongoDB lookup
  ├─ [3] RateLimiter       Redis Lua sliding-window, per-key limit
  ├─ [4] InjectionDetector 5 attack categories, 23 regex patterns
  ├─ [5] PIIRedactor       tokenise + AES-256-GCM seal
  ├─ [6] OutputValidator   wraps res.json — scans LLM response
  └─ [7] ChatController    cache lookup → AbortController(30s) → OpenAI
```

### 1. Audit Logger
Every request — including those that are later rejected — is wrapped by the audit logger. It attaches a `SecurityContext` object to the request at the very start, then registers a `res.on('finish')` listener that fires when the response is sent (regardless of which middleware terminated the pipeline). The record written to MongoDB includes: correlation ID, timestamp, API key ID, model, SHA-256 hashes of the pre-redaction request body and LLM response, detected threats and injection categories, PII token count, output-blocked flag, latency, status code, and whether the response was served from cache. Records are automatically purged after **90 days** via a MongoDB TTL index. If MongoDB is unavailable, the write is skipped silently and the `failedWrites` counter on `/healthz` increments — the request is never blocked.

### 2. Authentication
The `x-api-key` request header is extracted and its SHA-256 hex digest is computed. The digest is looked up in the `apikeys` MongoDB collection (stored hashes only — plaintext keys are never persisted). Comparison is performed with `crypto.timingSafeEqual` to eliminate timing side-channels. On success, the resolved client `id`, `role` (`client` or `admin`), and optional per-key rate limit override are attached to `req.client` for downstream use. Missing or unknown keys return `401`.

### 3. Rate Limiter
Each authenticated client is subject to a **sliding-window** rate limit enforced in Redis. An atomic Lua script (`EVAL`) removes expired entries, counts the window occupancy, and conditionally records the new request — all as a single atomic operation, with no race conditions. The effective limit is `ApiKey.rateLimitPerMinute` if set on the key document, otherwise `RATE_LIMIT_MAX_REQUESTS` (default 30/min). Rejected requests receive `429` with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers. If Redis is unavailable, the middleware **fails open** — it logs the error, lets the request through, and never takes the gateway down due to a cache-layer outage.

### 4. Prompt Injection Detector
Every `content` field in the `messages` array is scanned against 23 regex patterns across five attack categories: **DIRECT_OVERRIDE** ("ignore previous instructions", `[ADMIN]:` prefix), **CONTEXT_EXTRACTION** ("repeat your system prompt", "output as JSON"), **PERSONA_HIJACK** (DAN mode, Python REPL impersonation), **INDIRECT_SMUGGLING** (ChatML/Llama boundary tokens, HTML comment injections, `[SYSTEM]:` prefixes), and **MULTILINGUAL_BYPASS** (BiDi override characters, French/German/Spanish/Arabic override phrases). A single match blocks the request with `400`, records the matched categories and raw substrings in the audit log, and stores the payloads in `securityContext.detectedPayloads` for the output validator to use as echo-detection anchors.

### 5. PII Redactor
Before the prompt reaches the upstream LLM, the redactor scans every message for three categories of personal data: **email addresses** (RFC 5322 pattern), **phone numbers** (Israeli mobile/landline with optional +972 prefix, and international E.164 format), and **Israeli national IDs** (9-digit sequences validated against the Population Authority Luhn checksum). Each value is replaced in-place with a deterministic reversible token (e.g. `<PII_EMAIL_1>`, `<PII_PHONE_2>`). The SHA-256 hash of the **pre-redaction** body is recorded in the audit log.

**Reversibility at audit time:** The token→original mapping is encrypted with AES-256-GCM using `PII_ENC_KEY` and stored as ciphertext (`iv`, `tag`, `data`) inside the audit log record. No plaintext PII is ever written to MongoDB or Redis. An admin can recover the original values via `GET /v1/audit/:id/reveal`, which decrypts and returns the full token→original map for that request. In production, `PII_ENC_KEY` should be managed by a KMS (HashiCorp Vault, AWS KMS) with automatic rotation.

### 6. Output Validator
The validator wraps `res.json()` to intercept the LLM response before it leaves the gateway. It checks the response body against: (a) secret-leakage patterns — OpenAI `sk-` keys, Anthropic `sk-ant-` keys, AWS Access Key IDs, AWS secret key patterns, JWT-shaped strings, and generic high-entropy API key assignments; (b) injection-echo indicators — phrases indicating the model was prompted to reveal its system instructions; (c) raw payload echo — whether the response contains any substring that originally triggered the injection detector. Any match replaces the response with `403 Response blocked by output security policy` and records the relevant threat flags in the audit log.

### 7. LLM Service — per-tenant cache + hard timeout

**Per-tenant response cache:** Before calling OpenAI, the service checks a Redis key scoped to `clientId + SHA-256(model + messages + max_tokens)`. On a hit the cached response is returned immediately (`cacheHit: true` in the audit log) with no OpenAI call and no token cost. On a miss the response is stored after a successful call with TTL of `LLM_CACHE_TTL_SECONDS` (default 5 min, set to `0` to disable). The cache key is built from the **PII-redacted** prompt, so no plaintext PII can land in Redis. Cache read/write failures fail-open and never block the request.

**Hard timeout:** Every `fetch` to OpenAI is wrapped in an `AbortController` with a deadline of `LLM_REQUEST_TIMEOUT_MS` (default 30 s). If the upstream hangs, the request is aborted and the gateway returns `503 Service Unavailable: LLM request timed out` — no socket or event-loop slot can be held open indefinitely.

---

## API reference

### `POST /v1/chat`

Proxies a chat completion request through the full security pipeline.

**Request headers:**
- `x-api-key: <client-key>` (**required**)
- `Content-Type: application/json`

**Request body** (max 1 MB):
```jsonc
{
  "model": "gpt-4o",          // optional — defaults to gpt-3.5-turbo
  "messages": [
    { "role": "user", "content": "Hello!" }
  ],
  "max_tokens": 1024          // optional — forwarded to OpenAI as-is
}
```

**Response headers (on every response):**
- `X-Request-ID: <uuid>` — correlation ID for tracing this request in the audit log
- `X-RateLimit-Limit: 30` — effective limit for this API key
- `X-RateLimit-Remaining: N` — requests remaining in the current window
- `X-RateLimit-Reset: <unix-ts>` — when the window resets

**Additional header on 429:**
- `Retry-After: <seconds>`

**Status codes:**
| Status | Meaning |
|---|---|
| `200` | Success — returns OpenAI-compatible completion object |
| `400` | Injection detected or malformed body (missing `messages` array) |
| `401` | Missing or invalid `x-api-key` |
| `403` | Insufficient role, or LLM response blocked by output validator |
| `413` | Request body exceeds 1 MB |
| `429` | Rate limit exceeded |
| `503` | Upstream LLM unavailable, timed out, or key not configured |

---

### `GET /v1/audit`

Admin-only. Returns paginated audit log entries from MongoDB, sorted newest-first.

**Query parameters:**
| Param | Description |
|---|---|
| `limit` | Number of records to return (1–500, default 50) |
| `offset` | Records to skip for pagination (default 0) |
| `since` | ISO 8601 timestamp — return only records at or after this time |
| `correlationId` | UUID — return the single entry for this request |
| `apiKeyId` | MongoDB ObjectId — filter by a specific API key |
| `onlyThreats` | `true` — return only records with injection, PII, or blocked output |

**Response:**
```json
{
  "total": 142,
  "limit": 50,
  "offset": 0,
  "logs": [
    {
      "correlationId": "a3f7b2c1-...",
      "timestamp": "2026-05-19T10:00:00.000Z",
      "apiKeyId": "...",
      "apiKeyHash": "625faa...",
      "endpoint": "/chat",
      "httpMethod": "POST",
      "statusCode": 200,
      "latencyMs": 412,
      "llmModel": "gpt-3.5-turbo",
      "cacheHit": false,
      "requestBodyHash": "sha256...",
      "responseBodyHash": "sha256...",
      "promptInjectionDetected": false,
      "injectionTypes": [],
      "piiDetected": true,
      "piiTokenCount": 2,
      "outputBlocked": false,
      "threatFlags": ["PII_DETECTED"],
      "errorMessage": null
    }
  ]
}
```

---

### `GET /v1/audit/:id/reveal`

Admin-only. Decrypts and returns the PII token→original mapping for a specific audit log entry. Requires `PII_ENC_KEY` to be configured.

**Response:**
```json
{
  "correlationId": "a3f7b2c1-...",
  "tokens": {
    "<PII_EMAIL_1>": "john@example.com",
    "<PII_PHONE_1>": "050-123-4567"
  }
}
```

Returns `{ "tokens": {}, "message": "No PII was detected in this request" }` when no PII was redacted.

---

### `GET /healthz`

Unauthenticated liveness/readiness probe. Returns `200` when all checks pass, `503` when any check fails.

```json
{
  "status": "ok | degraded",
  "timestamp": "2026-05-19T10:00:00.000Z",
  "checks": {
    "mongodb":     { "status": "ok | down" },
    "redis":       { "status": "ok | down" },
    "llmProvider": { "status": "ok | missing_key" },
    "auditLog":    { "status": "ok | degraded", "failedWrites": 0 }
  }
}
```

`auditLog.failedWrites` counts audit log write failures since process start. A non-zero value means audit records have been lost and investigation is needed.

---

## Inserting API keys

Keys are stored as SHA-256 hashes. To create a client key:

```bash
# 1. Compute the hash of your chosen key string
node -e "const c=require('crypto'); console.log(c.createHash('sha256').update('your-key-here').digest('hex'))"

# 2. Insert into MongoDB (replace hash and name)
docker exec -it securellm-mongo mongosh \
  -u admin -p password --authenticationDatabase admin \
  --eval "db.getSiblingDB('securellm').apikeys.insertOne({
    keyHash: '<hash-from-step-1>',
    name: 'My Client',
    role: 'client',    // or 'admin'
    isActive: true,
    rateLimitPerMinute: null   // null = use global RATE_LIMIT_MAX_REQUESTS
  })"

# 3. Use the key in requests
curl -H "x-api-key: your-key-here" http://localhost:3000/v1/chat ...
```

---

## Running tests

```bash
npm test               # 72 Vitest tests — injection, PII, adversarial, resilience
npm run test:coverage  # coverage report
npm run typecheck      # TypeScript strict-mode compile check
```

The test suite covers: Appendix A injection corpus (25 tests), PII-D1/D2/D3 scenarios (26 tests), concurrency / rate-limit race conditions / ReDoS / LLM failure injection / malformed inputs / audit-logger async resilience (21 tests).

---

### PII Redaction & Reversibility Architecture

#### How it works

Every inbound message is scanned for three categories of personal data — **email addresses**, **phone numbers** (Israeli mobile/landline + international E.164), and **Israeli national IDs** (Luhn-validated). Each value is replaced in-place with a deterministic reversible token before the prompt reaches OpenAI.

The token→original mapping is encrypted using **AES-256-GCM** (authenticated encryption) with a fresh 96-bit random IV generated per request. The resulting subdocument is stored inside the MongoDB audit record:

```json
"sealedPiiMap": {
  "iv":   "<base64, 12 bytes — unique per request>",
  "tag":  "<base64, 16 bytes — GCM authentication tag>",
  "data": "<base64, AES-256-GCM ciphertext>"
}
```

No plaintext PII is written to MongoDB or Redis at any point. The GCM authentication tag means any tampering with the stored ciphertext is detected and rejected before a single byte of plaintext is returned.

#### Verified working — live terminal output

```bash
# 1. Send a request containing real PII
curl -X POST "http://localhost:3000/v1/chat" \
  -H "x-api-key: <client-key>" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"email: guy@hit.ac.il, phone: 052-1234567, ID: 123456782"}]}'
# → 200 OK — LLM received <PII_EMAIL_1>, <PII_PHONE_1>, <PII_IL_ID_1>, not the real values

# 2. Admin recovers original values from the audit log
curl -X GET "http://localhost:3000/v1/audit/6a0c2e079caf5e9c3db39f8b/reveal" \
  -H "x-api-key: <admin-key>"
```

**Actual response (verified):**
```json
{
  "correlationId": "b8390419-a580-403a-bcd5-a30b4536b7d4",
  "tokens": {
    "<PII_EMAIL_1>": "guy@hit.ac.il",
    "<PII_PHONE_1>": "052-1234567",
    "<PII_IL_ID_1>": "123456782"
  }
}
```

Recovery is gated behind `role: admin` RBAC. A `client` key receives `403 Forbidden`. The decryption key (`PII_ENC_KEY`) never leaves the server environment.

---

## Security & Compliance: PII Reversibility Architecture

The gateway enforces a **zero plaintext** policy: personal data is never written to any persistent store in its original form.

```
Inbound request
  │
  ▼
[PIIRedactor] ── detects email / phone / IL-ID
  │               replaces with <PII_EMAIL_1> etc.
  │               builds token → original Map in memory
  │
  ├──► req.piiMap (in-memory, per-request lifetime only)
  │
  └──► AES-256-GCM encrypt(Map, PII_ENC_KEY, random IV)
         │
         ▼
       { iv, tag, data }  ←── stored in AuditLog.sealedPiiMap (MongoDB)
                               no plaintext PII in DB or Redis

Admin recovery path (RBAC: role=admin only)
  GET /v1/audit/:id/reveal
    │
    └──► AES-256-GCM decrypt(sealedPiiMap, PII_ENC_KEY)
           │
           ▼
         { "<PII_EMAIL_1>": "john@example.com", ... }
```

### Why AES-256-GCM

AES-256-GCM is an **authenticated encryption** scheme. The 16-byte authentication tag (`tag` field) cryptographically binds the ciphertext to the IV and key. Any bit-flip in the stored ciphertext causes decryption to throw before returning a single byte — preventing silent data corruption or tampering. A non-authenticated mode (e.g. AES-CBC) would decrypt corrupted data silently.

### Key management

`PII_ENC_KEY` is a 32-byte key supplied as a hex environment variable. Each request uses a **fresh 96-bit random IV**, so encrypting the same mapping twice produces different ciphertexts. In production, `PII_ENC_KEY` should be managed by a KMS (AWS KMS, HashiCorp Vault) with automatic rotation and per-request envelope encryption.

### Access control

The `/v1/audit/:id/reveal` endpoint requires `role: admin`. Standard client keys receive `403 Forbidden`. The key hash and role are validated on every request with `crypto.timingSafeEqual` to prevent timing-based enumeration.

---

## Known limitations

- **PII key management**: `PII_ENC_KEY` is read from an environment variable. Production deployments should use a KMS (AWS KMS, HashiCorp Vault) with automatic key rotation and per-request envelope encryption.
- **Semantic obfuscation**: regex-based detection cannot catch sophisticated multi-turn social engineering or payloads split across multiple messages. An LLM-as-a-judge secondary call would close this gap.
- **Base64 / encoding bypass**: payloads that are base64- or URL-encoded before reaching the gateway are not decoded and re-scanned. The upstream LLM may decode and execute them.
- **Language coverage**: the multilingual bypass detector covers BiDi override characters and a fixed set of European and Arabic phrases. Novel scripts or transliteration attacks may evade it.
- **Single-node Redis**: the Lua sliding-window script is atomic on a single Redis node but not on a Redis Cluster. Multi-shard deployments require a cluster-aware rate-limiting strategy (e.g. `redis-cell` or per-shard key routing).
- **Cache scope**: the response cache is per-tenant (per API key). Identical prompts from different keys are not deduplicated. A shared cache with consent-aware key design would improve cost efficiency in multi-tenant deployments.
