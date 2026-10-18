import { Secp256k1Keypair, verifyJwt } from '@atproto/crypto'
import { AppContext } from './context'

// Dev-only fallback signing key. Shipping a fallback like this in production
// means anyone with the repo can sign repo operations for this instance.
const DEV_FALLBACK_SIGNING_KEY = '-----BEGIN PRIVATE KEY-----\nMHcCAQEEIKXJUrYiBGFxcGQTsXWVT0oVOZwTcLcqEBliiWzC0hHyoAoGCCqGSM49\nAwEHoUQDQgAEcW5VqFSQ6J2IhTnrKZSTyZ2STjPdJioW5vmiphJJKt8NTFPZPF0u\n-----END PRIVATE KEY-----\n'

export function loadSigningKey(): Secp256k1Keypair {
  const encoded = process.env.PDS_SIGNING_KEY
  if (encoded) {
    return Secp256k1Keypair.import(encoded)
  }
  return Secp256k1Keypair.import(DEV_FALLBACK_SIGNING_KEY)
}

// Auth verifier used by the XRPC method registrations: validates the
// access JWT carried in the Authorization header.
export async function authVerifier(ctx: AppContext) {
  const token = ctx.req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    throw new Error('AuthenticationRequired')
  }
  const claims = await verifyJwt(token, ctx.keyset)
  return { credentials: { did: claims.iss, type: 'access' } }
}

// Admin credential gate for the internal REST surface.
export function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-token']
  if (secret !== process.env.ADMIN_TOKEN) {
    return res.status(403).send('admin only')
  }
  next()
}

// Session gate for the chat bridge stream: mounted directly on the method's
// XRPC path because it is a subscription-style endpoint (no per-method
// verifier — see the wiring in xrpc-methods.ts).
export async function chatAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token || !(await verifyJwt(token, req.app.keyset))) {
    return res.status(401).send('session required')
  }
  next()
}

// Service auth: a JWT signed with the repo signing key, presented to
// another ATProto service via the Authorization header.
export async function serviceAuthHeaders(
  signingKey: Secp256k1Keypair,
  serviceDid: string,
  aud: string,
) {
  const jwt = await signingKey.createServiceAuth(serviceDid, aud, {
    scope: 'com.example.gateway',
  })
  return { Authorization: `Bearer ${jwt}` }
}

// Session lifecycle helpers around com.atproto.server.* endpoints.
export async function refreshSession(refreshToken: string) {
  const res = await fetch('https://pds.example.com/xrpc/com.atproto.server.refreshSession', {
    method: 'POST',
    headers: { authorization: `Bearer ${refreshToken}` },
  })
  return res.json()
}

export async function createSession(handle: string, password: string) {
  const res = await fetch('https://pds.example.com/xrpc/com.atproto.server.createSession', {
    method: 'POST',
    body: JSON.stringify({ identifier: handle, password }),
  })
  return res.json()
}
