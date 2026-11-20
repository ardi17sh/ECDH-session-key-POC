import express from 'express'
import crypto from 'node:crypto'

const app = express()
app.use(express.json())

// sid -> { aesKey, reqSeq, createdAt }. POC: no TTL, no persistence.
const sessions = new Map()

function encrypt(aesKey, obj) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv)
  // AES-GCM ciphertext followed by the 16-byte tag, as Web Crypto expects.
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final(), cipher.getAuthTag()])
  return { iv: iv.toString('base64'), data: data.toString('base64') }
}

function decrypt(aesKey, { iv, data }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'base64'))
  const sealed = Buffer.from(data, 'base64')
  decipher.setAuthTag(sealed.subarray(-16))
  const plain = Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()])
  return JSON.parse(plain.toString('utf8'))
}

function parsePublicKey(jwk) {
  if (jwk?.kty !== 'EC' || jwk?.crv !== 'P-256') return null
  try {
    return crypto.createPublicKey({ key: jwk, format: 'jwk' })
  } catch {
    return null
  }
}

// Fresh server key pair per call: the session key is always derived from two ephemeral keys.
function deriveSessionKey(clientKey) {
  const serverKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  return {
    aesKey: crypto.diffieHellman({ privateKey: serverKeys.privateKey, publicKey: clientKey }),
    serverPublicKey: serverKeys.publicKey.export({ format: 'jwk' }),
  }
}

function getSession(req) {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1]
  return sid ? sessions.get(sid) : undefined
}

// Encrypted request body -> plaintext, rejecting replays: seq never goes backwards.
function openRequest(session, body) {
  if (!body?.iv || !body?.data) return { error: 400, message: 'encrypted body required' }
  let payload
  try {
    payload = decrypt(session.aesKey, body)
  } catch {
    return { error: 400, message: 'request failed to decrypt' }
  }
  if (!Number.isInteger(payload.seq) || payload.seq <= session.reqSeq) {
    return { error: 409, message: 'stale or replayed request' }
  }
  session.reqSeq = payload.seq
  return { payload }
}

// Once per login session: ECDH handshake, server derives the shared AES key.
app.post('/api/handshake', (req, res) => {
  const clientKey = parsePublicKey(req.body?.publicKey)
  if (!clientKey) return res.status(400).json({ error: 'P-256 public key required' })

  const session = deriveSessionKey(clientKey)
  const sid = crypto.randomUUID()
  sessions.set(sid, { aesKey: session.aesKey, reqSeq: 0, createdAt: Date.now() })
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/`)
  res.json({ publicKey: session.serverPublicKey })
})

// Every API call: encrypted request in, encrypted response out.
app.post('/api/data', (req, res) => {
  const session = getSession(req)
  if (!session) return res.status(401).json({ error: 'no session, renegotiate' })
  const { payload, error, message } = openRequest(session, req.body)
  if (error) return res.status(error).json({ error: message })

  res.json(encrypt(session.aesKey, {
    seq: payload.seq,
    message: 'This payload was AES-GCM encrypted with the ECDH-derived session key.',
    secret: `secret-${crypto.randomBytes(4).toString('hex')}`,
    serverTime: new Date().toISOString(),
  }))
})

// Both sides swap to freshly derived keys; the reply itself travels under the old key.
app.post('/api/rekey', (req, res) => {
  const session = getSession(req)
  if (!session) return res.status(401).json({ error: 'no session, renegotiate' })
  const { payload, error, message } = openRequest(session, req.body)
  if (error) return res.status(error).json({ error: message })

  const nextClientKey = parsePublicKey(payload.publicKey)
  if (!nextClientKey) return res.status(400).json({ error: 'P-256 public key required' })

  const next = deriveSessionKey(nextClientKey)
  const reply = encrypt(session.aesKey, { publicKey: next.serverPublicKey })
  session.aesKey = next.aesKey
  session.reqSeq = 0
  res.json(reply)
})

// Refresh or logout: key discarded server-side; the browser must drop its key too.
app.post('/api/logout', (req, res) => {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1]
  if (sid) sessions.delete(sid)
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  res.json({ ok: true })
})

const port = 3001
app.listen(port, () => console.log(`api on http://localhost:${port}`))
