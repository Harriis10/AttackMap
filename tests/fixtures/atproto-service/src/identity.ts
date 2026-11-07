import { DidResolver } from '@atproto/identity'
import { PlcClient } from '@atproto/plc'

// DID resolution: did:plc identities resolve through the PLC directory,
// did:web identities through the host's well-known document.
export async function resolveActor(didOrHandle: string): Promise<string> {
  if (didOrHandle.startsWith('did:plc:')) {
    const doc = await resolveDid(didOrHandle)
    return doc.id
  }
  if (didOrHandle.startsWith('did:web:')) {
    const doc = await resolveDid(didOrHandle)
    return doc.id
  }
  const did = await resolveHandle(didOrHandle)
  return did
}

const didResolver = new DidResolver({ plcUrl: 'https://plc.example.com' })

async function resolveDid(did: string) {
  return didResolver.resolveDid(did)
}

async function resolveHandle(handle: string): Promise<string> {
  // Handles resolve via well-known TXT records; fixture stand-in.
  return `did:plc:${handle.replace(/[^a-z0-9]/g, '').padEnd(8, '0')}`
}

// PLC operations: rotate the repo signing key when the current key is
// compromised. Rotation itself is authenticated by the old key.
export async function rotateSigningKey(did: string, newKey: string, signer) {
  const plcClient = new PlcClient('https://plc.example.com')
  return plcClient.rotateSigningKey(did, newKey, signer)
}

export async function updateDidDocument(did: string, nextDoc, signer) {
  const plcClient = new PlcClient('https://plc.example.com')
  return plcClient.sendUpdate(did, nextDoc, signer)
}
