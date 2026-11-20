# ECDH session key POC

Express API + Vue 3 frontend, in one pnpm workspace. ECDH P-256 handshake once per
login, then every API response is AES-256-GCM encrypted under the derived key.

![ECDH session key flow](./session_key_ecdh_flow.png)

```
apps/
  server/   Express API, :3001, sessions in memory
  web/      Vue 3 + Vite, :5173, proxies /api to the server
```

The browser only ever talks to one origin (the Vite dev server), so cookies and
`crypto.subtle` both just work.

```sh
pnpm install
pnpm dev          # http://localhost:5173
```

`pnpm dev` runs both packages in parallel; `pnpm dev:web` / `pnpm dev:server`
run one side.

## Flow

| Step | Where | Code |
|---|---|---|
| Generate ECDH pair, send public key | browser | `apps/web/src/App.vue` `negotiate` |
| Derive AES key, reply with server public key | server | `apps/server/index.js` `/api/handshake` |
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
