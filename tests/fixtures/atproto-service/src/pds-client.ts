import axios from 'axios'
import { BlobRef } from '@atproto/xrpc-server'

// Upstream PDS this gateway fronts (synthetic example.com host).
const pdsUrl = 'https://pds.example.com'

// AppView endpoint used for hydrated timeline reads.
const appviewUrl = 'https://appview.example.com'

export async function uploadBlob(pds: string, bytes: Uint8Array, mimeType: string) {
  const res = await axios.post(`${pds}/xrpc/com.atproto.repo.uploadBlob`, bytes, {
    headers: { 'content-type': mimeType },
  })
  return res.data.blob as BlobRef
}

export async function putBlob(pds: string, did: string, cid: string, bytes: Uint8Array) {
  return axios.post(`https://pds.example.com/xrpc/com.atproto.sync.putBlob`, bytes, {
    params: { did, cid },
  })
}

export async function getBlob(pds: string, did: string, cid: string) {
  const res = await axios.get(`${pdsUrl}/xrpc/com.atproto.sync.getBlob`, {
    params: { did, cid },
    responseType: 'arraybuffer',
  })
  return res.data
}

export async function describeRepo(did: string) {
  const res = await axios.get(`${pdsUrl}/xrpc/com.atproto.repo.describeRepo`, {
    params: { did },
  })
  return res.data
}

export async function getTimeline(did: string) {
  const res = await axios.get(`${appviewUrl}/xrpc/app.bsky.feed.getTimeline`, {
    params: { viewer: did },
  })
  return res.data
}
