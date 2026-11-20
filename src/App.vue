<script setup>
import { onMounted, ref } from 'vue'

const key = ref(null);
const serverPublicKey = ref(null);
const wire = ref(null);
const plain = ref(null);
const log = ref([]);
const error = ref('');

const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const note = (msg) => log.value.unshift(`${new Date().toLocaleTimeString()} ${msg}`);

// Once per login session. The AES key is derived into a non-extractable handle:
// JS (and any injected script) can use it but never read its bytes.
async function negotiate() {
  error.value = '';
  plain.value = null;
  wire.value = null;
  try {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    note('browser: generated ECDH P-256 key pair');
    const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);

    const res = await fetch('/api/handshake', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ publicKey }),
    });
    if (!res.ok) throw new Error(`handshake failed: ${res.status}`);
    const { publicKey: serverJwk } = await res.json();
    serverPublicKey.value = serverJwk;
    note('server: replied with its public key');

    const serverKey = await crypto.subtle.importKey('jwk', serverJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    key.value = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: serverKey },
      pair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    note('browser: derived the same AES-256 key (non-extractable, memory only)');
  } catch (e) {
    error.value = e.message;
    note(`error: ${e.message}`);
  }
}

// Every API call: server encrypts with AES-GCM + random IV, browser decrypts.
async function fetchData() {
  if (!key.value) return negotiate().then(fetchData);
  error.value = '';
  try {
    const res = await fetch('/api/data');
    if (!res.ok) throw new Error(`request failed: ${res.status}`);
    const payload = await res.json();
    wire.value = payload;
    note(`server: encrypted response (iv ${payload.iv.slice(0, 12)}…)`);
    const bytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(payload.iv) },
      key.value,
      b64ToBytes(payload.data),
    );
    plain.value = JSON.parse(new TextDecoder().decode(bytes));
    note('browser: decrypted with Web Crypto');
  } catch (e) {
    error.value = e.message;
    note(`error: ${e.message}`);
  }
}

// Refresh or logout: drop the key, renegotiate next time.
async function logout() {
  key.value = null;
  serverPublicKey.value = null;
  wire.value = null;
  plain.value = null;
  await fetch('/api/logout', { method: 'POST' }).catch(() => {});
  note('logout: key discarded, session gone');
}

onMounted(negotiate);
</script>

<template>
  <main>
    <h1>ECDH session key POC</h1>
    <p class="sub">Express + Vue. Handshake once, then every response is AES-GCM encrypted.</p>

    <section class="card">
      <div class="row">
        <span>Session key</span>
        <strong :class="key ? 'ok' : 'bad'">{{ key ? 'AES-256-GCM ready (non-extractable)' : 'none' }}</strong>
      </div>
      <div class="row">
        <span>Server public key</span>
        <code class="ellipsis">{{ serverPublicKey ? serverPublicKey.x.slice(0, 16) + '…' : '—' }}</code>
      </div>
      <div class="actions">
        <button @click="fetchData">Request encrypted data</button>
        <button class="ghost" @click="negotiate">Renegotiate</button>
        <button class="ghost" @click="logout">Logout</button>
      </div>
    </section>

    <p v-if="error" class="error">{{ error }}</p>

    <section v-if="wire" class="card">
      <h2>On the wire (ciphertext)</h2>
      <pre>{{ JSON.stringify(wire, null, 2) }}</pre>
    </section>

    <section v-if="plain" class="card">
      <h2>Decrypted in browser</h2>
      <pre>{{ JSON.stringify(plain, null, 2) }}</pre>
    </section>

    <section class="card">
      <h2>Flow log</h2>
      <pre class="log">{{ log.join('\n') }}</pre>
    </section>
  </main>
</template>

<style>
:root { color-scheme: light dark; }
body { margin: 0; font: 15px/1.5 system-ui, sans-serif; background: #f6f7f9; color: #1c2333; }
main { max-width: 720px; margin: 0 auto; padding: 40px 20px 80px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: #6b7385; margin: 0 0 10px; }
.sub { margin: 0 0 24px; color: #6b7385; }
.card { background: #fff; border: 1px solid #e3e6eb; border-radius: 10px; padding: 16px 18px; margin-bottom: 14px; }
.row { display: flex; justify-content: space-between; gap: 16px; padding: 4px 0; }
.row > span { color: #6b7385; }
.ok { color: #0f7b3f; }
.bad { color: #b42318; }
.ellipsis { font-family: ui-monospace, monospace; font-size: 12px; }
.actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
button { font: inherit; padding: 8px 14px; border-radius: 8px; border: 1px solid #1c2333; background: #1c2333; color: #fff; cursor: pointer; }
button.ghost { background: transparent; color: #1c2333; border-color: #cfd4dc; }
button:hover { opacity: .88; }
pre { margin: 0; padding: 12px; background: #f6f7f9; border-radius: 8px; font: 12px/1.55 ui-monospace, monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.log { max-height: 200px; overflow-y: auto; }
.error { color: #b42318; margin: 0 0 14px; }
</style>
