import type { QueryBuilder } from '@atlex/orm'

import type { SessionStore } from '../../contracts/SessionStore.js'

/**
 * Database-backed session store using a `sessions` table.
 */
export class DatabaseStore implements SessionStore {
  private readonly query: () => QueryBuilder

  private readonly table: string

  /**
   * @param query - Factory that returns a fresh {@link QueryBuilder}.
   * @param table - Sessions table name.
   */
  public constructor(query: () => QueryBuilder, table: string) {
    this.query = query
    this.table = table
  }

  /**
   * @inheritdoc
   */
  public async open(_savePath: string, _sessionName: string): Promise<void> {
    /* noop */
  }

  /**
   * @inheritdoc
   */
  public async close(): Promise<void> {
    /* noop */
  }

  /**
   * @inheritdoc
   */
  public async read(sessionId: string): Promise<string> {
    const row = await this.query()
      .table(this.table)
      .where('id', sessionId)
      .first<{ payload: string }>()
    return row?.payload ?? ''
  }

  /**
   * @inheritdoc
   */
  public async write(sessionId: string, data: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    const existing = await this.query()
      .table(this.table)
      .where('id', sessionId)
      .first<{ id: string }>()
    if (existing === null || existing === undefined) {
      // QueryBuilder.insert(single) assumes a numeric `id` on Postgres (`returning "id"`).
      // Session ids are UUID strings; use a one-row bulk insert.
      await this.query()
        .table(this.table)
        .insert([
          {
            id: sessionId,
            user_id: null,
            ip_address: null,
            user_agent: null,
            payload: data,
            last_activity: now,
          },
        ])
      return
    }
    await this.query().table(this.table).where('id', sessionId).update({
      payload: data,
      last_activity: now,
    })
  }

  /**
   * @inheritdoc
   */
  public async destroy(sessionId: string): Promise<void> {
    await this.query().table(this.table).where('id', sessionId).delete()
  }

  /**
   * @inheritdoc
   */
  public async gc(maxLifetime: number): Promise<number> {
    const cutoff = Math.floor(Date.now() / 1000) - maxLifetime
    return await this.query().table(this.table).where('last_activity', '<', cutoff).delete()
  }
}
