// Handlers for the wired XRPC methods. Each handler receives the shared
// app context plus the method's parsed input.

export async function postStatus(ctx, input) {
  const did = input.auth.credentials.did
  const uri = await ctx.db.status.create({
    data: {
      authorDid: did,
      statusText: input.statusText,
      createdAt: new Date().toISOString(),
    },
  })
  return { uri: `at://${did}/com.example.status/${uri.id}`, cid: uri.cid }
}

export async function listStatuses(ctx, input) {
  // Reads any actor's statuses by the requester-supplied `actor` param.
  const rows = await ctx.db.status.findMany({
    where: { authorDid: input.actor },
    take: input.limit ?? 50,
  })
  return { statuses: rows }
}

export async function reportContent(ctx, input) {
  // Writes a moderation record from unauthenticated input.
  const report = await ctx.db.moderationReport.create({
    data: {
      subjectUri: input.subjectUri,
      reasonType: input.reasonType,
      reasonText: input.reasonText ?? null,
      reporterDid: null,
    },
  })
  return { id: report.id }
}

export async function purgeAccount(ctx, input) {
  // Privileged destructive action; only reachable through the verified
  // admin credential path (see the auth verifier on the registration).
  await ctx.db.account.deleteMany({ where: { did: input.did } })
  return {}
}

export async function getProfileChecked(ctx, input) {
  const profile = await ctx.db.profile.findUnique({
    where: { did: input.actor },
  })
  if (profile && profile.did !== input.auth.credentials.did) {
    // Ownership check: only the profile owner may read the private view.
    if (profile.visibility === 'private') {
      throw new Error('ProfileNotFound')
    }
  }
  return { did: profile.did, displayName: profile.displayName }
}
