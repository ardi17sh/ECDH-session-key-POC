import express from 'express'
import crypto from 'node:crypto'
import { createServer as createViteServer } from 'vite'

const app = express()
app.use(express.json())

// sessionId -> { aesKey, createdAt }. POC: no TTL, no persistence.
const sessions = new Map()

function encrypt(aesKey, obj) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv)
  // AES-GCM ciphertext followed by the 16-byte tag, as Web Crypto expects.
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final(), cipher.getAuthTag()])
  return { iv: iv.toString('base64'), data: data.toString('base64') }
}

function getSession(req) {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1]
  return sid ? sessions.get(sid) : undefined
}

// Once per login session: ECDH handshake, server derives the shared AES key.
app.post('/api/handshake', (req, res) => {
  const jwk = req.body?.publicKey
  if (jwk?.kty !== 'EC' || jwk?.crv !== 'P-256') return res.status(400).json({ error: 'P-256 public key required' })

  let clientKey
  try {
    clientKey = crypto.createPublicKey({ key: jwk, format: 'jwk' })
  } catch {
    return res.status(400).json({ error: 'invalid public key' })
  }

  const serverKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const aesKey = crypto.diffieHellman({ privateKey: serverKeys.privateKey, publicKey: clientKey })

  const sid = crypto.randomUUID()
  sessions.set(sid, { aesKey, createdAt: Date.now() })
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/`)
  res.json({ publicKey: serverKeys.publicKey.export({ format: 'jwk' }) })
})

// Every API call: encrypted response under the session key.
app.get('/api/data', (req, res) => {
  const session = getSession(req)
  if (!session) return res.status(401).json({ error: 'no session, renegotiate' })
  res.json(encrypt(session.aesKey, {
    message: 'This payload was AES-GCM encrypted with the ECDH-derived session key.',
    secret: `secret-${crypto.randomBytes(4).toString('hex')}`,
    serverTime: new Date().toISOString(),
  }))
})

// Refresh or logout: key discarded server-side; the browser must drop its key too.
app.post('/api/logout', (req, res) => {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1]
  if (sid) sessions.delete(sid)
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  res.json({ ok: true })
})

const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' })
app.use(vite.middlewares)

const port = 3001
app.listen(port, () => console.log(`http://localhost:${port}`))
