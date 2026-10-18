// Thin data-access layer for the gateway (fixture stand-in for Prisma-like access).

export class Database {
  status: StatusTable
  profile: ProfileTable
  account: AccountTable
  moderationReport: ModerationReportTable

  private constructor() {
    this.status = new StatusTable()
    this.profile = new ProfileTable()
    this.account = new AccountTable()
    this.moderationReport = new ModerationReportTable()
  }

  static connect(url: string): Database {
    return new Database()
  }
}

class StatusTable {
  async create(args) { return { id: 1, cid: 'bafyexample' } }
  async findMany(args) { return [] }
}

class ProfileTable {
  async findUnique(args) {
    return { did: args.where.did, displayName: 'example', visibility: 'public' }
  }
}

class AccountTable {
  async deleteMany(args) { return { count: 1 } }
}

class ModerationReportTable {
  async create(args) { return { id: 1 } }
}
