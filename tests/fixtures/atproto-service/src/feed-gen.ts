// Custom feed generator served by this deployment. The generator declares
// itself in its DID document via a BskyFeedGenerator service entry.

export const FEEDGEN_DID = 'did:plc:feedgenexample00'

export const FEEDGEN_DID_DOC = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: FEEDGEN_DID,
  alsoKnownAs: ['handle:feedgen.example.com'],
  verificationMethod: [],
  service: [
    {
      id: '#atproto_pds',
      type: 'AtprotoPersonalDataServer',
      serviceEndpoint: 'https://pds.example.com',
    },
    {
      id: '#bsky_app',
      type: 'BskyAppView',
      serviceEndpoint: 'https://appview.example.com',
    },
    {
      id: '#feed_generator',
      type: 'BskyFeedGenerator',
      serviceEndpoint: 'https://feedgen.example.com',
    },
  ],
}

// The skeleton endpoint AppView calls to materialize the custom feed.
export async function getFeedSkeleton(req, res) {
  const feed = await req.context.db.feedSkeleton.findMany({
    where: { feedUri: req.query.feed },
    take: 30,
  })
  return res.json({ feed: feed.map((item) => ({ post: item.postUri })) })
}

export async function describeGenerator(req, res) {
  return res.json({
    did: FEEDGEN_DID,
    displayName: 'example firehose highlights',
  })
}
