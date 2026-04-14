import type { QueryBuilder } from '@atlex/orm'

import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { UserProvider } from '../contracts/UserProvider.js'
import { type HashManager } from '../hashing/HashManager.js'

type Row = Record<string, unknown>

/**
 * Loads users from a SQL table via {@link QueryBuilder}.
 */
export class DatabaseUserProvider implements UserProvider {
  private readonly query: () => QueryBuilder

  private readonly table: string

  private readonly hash: HashManager

  private readonly emailColumn: string

  private readonly hydrate: (row: Row) => Authenticatable

  /**
   * @param query - Factory for a fresh query builder.
   * @param table - Users table.
   * @param hash - Password hasher.
   * @param hydrate - Maps a DB row to an {@link Authenticatable}.
   * @param emailColumn - Email/login column name.
   * @param passwordColumn - Hashed password column name.
   */
  public constructor(
    query: () => QueryBuilder,
    table: string,
    hash: HashManager,
    hydrate: (row: Row) => Authenticatable,
    emailColumn = 'email',
    passwordColumn = 'password',
  ) {
    this.query = query
    this.table = table
    this.hash = hash
    this.hydrate = hydrate
    this.emailColumn = emailColumn
    void passwordColumn
  }

  /**
   * @inheritdoc
   */
  public async retrieveById(id: string | number): Promise<Authenticatable | null> {
    const row = await this.query().table(this.table).where('id', id).first<Row>()
    return row === null ? null : this.hydrate(row)
  }

  /**
   * @inheritdoc
   */
  public async retrieveByToken(
    id: string | number,
    token: string,
  ): Promise<Authenticatable | null> {
    const user = await this.retrieveById(id)
    if (user === null) {
      return null
    }
    const remember = user.getRememberToken()
    if (remember === null) {
      return null
    }
    return (await this.hash.check(token, remember)) ? user : null
  }

  /**
   * @inheritdoc
   */
  public async updateRememberToken(user: Authenticatable, token: string): Promise<void> {
    const id = user.getAuthIdentifier()
    user.setRememberToken(token)
    await this.query()
      .table(this.table)
      .where(user.getAuthIdentifierName(), id)
      .update({ [user.getRememberTokenName()]: token })
  }

  /**
   * @inheritdoc
   */
  public async retrieveByCredentials(
    credentials: Record<string, unknown>,
  ): Promise<Authenticatable | null> {
    const email = credentials.email
    if (typeof email !== 'string' || email.length === 0) {
      return null
    }
    const row = await this.query().table(this.table).where(this.emailColumn, email).first<Row>()
    return row === null ? null : this.hydrate(row)
  }

  /**
   * @inheritdoc
   */
  public async validateCredentials(
    user: Authenticatable,
    credentials: Record<string, unknown>,
  ): Promise<boolean> {
    const password = credentials.password
    if (typeof password !== 'string') {
      return false
    }
    return await this.hash.check(password, user.getAuthPassword())
  }
}
