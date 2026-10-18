// Subscribes to the relay firehose (repo event stream) and projects commits
// into the local read models.

const RELAY_HOST = 'wss://relay.example.com'

type FirehoseEvent =
  | { $type: 'com.atproto.sync.subscribeRepos#commit'; repo: string; ops: unknown[] }
  | { $type: 'com.atproto.sync.subscribeRepos#account'; did: string; active: boolean }
  | { $type: 'com.atproto.sync.subscribeRepos#identity'; did: string; handle: string }

export async function runFirehose(onEvent: (evt: FirehoseEvent) => Promise<void>) {
  const stream = await subscribeRepos(`${RELAY_HOST}/xrpc/com.atproto.sync.subscribeRepos`, {
    cursor: await loadCursor(),
  })
  for await (const evt of stream) {
    if (evt.$type === 'com.atproto.sync.subscribeRepos#commit') {
      await persistOps(evt.repo, evt.ops)
    } else if (evt.$type === 'com.atproto.sync.subscribeRepos#identity') {
      await refreshIdentity(evt.did, evt.handle)
    }
    await onEvent(evt)
  }
}

async function subscribeRepos(url: string, opts: { cursor?: number }) {
  throw new Error('implemented by the transport layer')
}

async function loadCursor(): Promise<number> {
  return 0
}

async function persistOps(repo: string, ops: unknown[]) {}

async function refreshIdentity(did: string, handle: string) {}
