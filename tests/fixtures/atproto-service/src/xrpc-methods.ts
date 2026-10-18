import { Server } from '@atproto/xrpc-server'
import { authVerifier } from './auth'
import { AppContext } from './context'
import {
  postStatus,
  listStatuses,
  reportContent,
  purgeAccount,
  getProfileChecked,
} from './status'

// Wires each lexicon method to its handler. The registration config's
// `auth` key is the per-method auth verifier used by @atproto/xrpc-server.
export function createXrpcServer(ctx: AppContext): Server {
  const server = new Server()

  server.method('com.example.status.post', {
    auth: authVerifier,
  }, (ctx2) => postStatus(ctx, ctx2))

  server.method('com.example.status.list', {
    auth: authVerifier,
  }, (ctx2) => listStatuses(ctx, ctx2))

  // Moderation reports are accepted anonymously today (no auth verifier).
  server.method('com.example.moderation.report', {}, (ctx2) => reportContent(ctx, ctx2))

  // Account purge is admin-only and verified against the admin credential.
  server.method('com.example.admin.purge', {
    auth: authVerifier,
  }, (ctx2) => purgeAccount(ctx, ctx2))

  // Profile reads with an ownership check are exposed as a checked variant.
  server.method('com.example.profile.getChecked', {
    auth: authVerifier,
  }, (ctx2) => getProfileChecked(ctx, ctx2))

  // Chat bridge stream: no per-method verifier; access is enforced by the
  // chatAuth middleware mounted on this exact path in index.ts.
  server.method('com.example.chat.send', {}, async (ctx2) => {
    await ctx.db.chatMessage.create({
      data: { senderDid: ctx2.input.senderDid, body: ctx2.input.body },
    })
  })

  return server
}
