# ECDH session key POC

Express + Vue demo of the diagram's flow: ECDH P-256 handshake once per login,
then every API response is AES-256-GCM encrypted under the derived key.

```sh
npm install
npm run dev          # http://localhost:3001
```

One process: Express hosts the Vite dev middleware, so client and API share an origin
(cookies and `crypto.subtle` both just work).

## Flow

| Step | Where | Code |
|---|---|---|
| Generate ECDH pair, send public key | browser | `src/App.vue` `negotiate` |
| Derive AES key, reply with server public key | server | `server/index.js` `/api/handshake` |
| Derive same AES key (non-extractable, memory only) | browser | `crypto.subtle.deriveKey(..., false, ['decrypt'])` |
| Encrypted response: AES-GCM, random IV, `{iv, data: ct‖tag}` base64 | server | `encrypt()` |
| Decrypt via Web Crypto | browser | `fetchData` |
| Logout drops key + session, next call renegotiates | both | `/api/logout` |

## Verify

- Click **Request encrypted data** twice: `iv`/`data` differ each time, plaintext never leaves the server.
- DevTools console: the derived `CryptoKey` is non-extractable, decrypt-only.
- **Logout**, then **Request encrypted data**: a fresh handshake happens transparently.
- `curl -X POST localhost:3001/api/handshake -d '{}' -H 'content-type: application/json'` → 400.
- `curl localhost:3001/api/data` → 401.

## POC limits (not production)

- Sessions live in a `Map`: lost on restart, unbounded (no TTL), single instance.
- Plain HTTP here; Web Crypto ECDH requires a secure context (`localhost` qualifies) — use HTTPS in real deployments.
- No replay binding, no request encryption (only responses), no key rotation beyond re-handshake.
- Auth is whatever the handshake proves — nothing. Add real user auth alongside it.
