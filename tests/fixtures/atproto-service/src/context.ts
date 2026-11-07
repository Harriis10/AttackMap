import { Database } from './db'
import { loadSigningKey } from './auth'
import { resolveActor } from './identity'

// Minimal app context handed to every XRPC handler.
export class AppContext {
  db: Database
  signingKey: ReturnType<typeof loadSigningKey>

  constructor(db: Database, signingKey: ReturnType<typeof loadSigningKey>) {
    this.db = db
    this.signingKey = signingKey
  }

  static async fromEnv(): Promise<AppContext> {
    const db = Database.connect(process.env.DATABASE_URL ?? 'postgresql://127.0.0.1:5432/gateway')
    const signingKey = loadSigningKey()
    return new AppContext(db, signingKey)
  }

  async actorDid(actor: string): Promise<string> {
    return resolveActor(actor)
  }
}
