import express from 'express'
import { AppContext } from './context'
import { createXrpcServer } from './xrpc-methods'
import { adminAuth, chatAuth } from './auth'

const HOST = 'example.com'
const PORT = 2583

export async function main() {
  const ctx = await AppContext.fromEnv()
  const app = express()
  app.use(express.json())

  // Internal REST admin surface, gated by the adminAuth middleware chain.
  app.use('/api/admin', adminAuth)

  // The chat bridge stream is gated by a path-exact middleware mount (it is
  // a subscription-style endpoint without a per-method verifier).
  app.use('/xrpc/com.example.chat.send', chatAuth)

  // The XRPC surface is mounted under /xrpc; per-method auth is resolved by
  // each method's auth verifier (see xrpc-methods.ts).
  const server = createXrpcServer(ctx)
  app.use('/xrpc', server.handler)

  app.get('/health', (_req, res) => {
    res.status(200).send('ok')
  })

  app.listen(PORT, HOST, () => {
    console.log(`gateway listening on ${HOST}:${PORT}`)
  })
}

main()
