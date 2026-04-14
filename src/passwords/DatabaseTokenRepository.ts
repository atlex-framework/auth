import { createHmac, randomBytes } from 'node:crypto'

import type { QueryBuilder } from '@atlex/orm'

import type { CanResetPassword } from '../contracts/CanResetPassword.js'
import { secureCompare } from '../support/secureCompare.js'

/**
 * Persists hashed password-reset tokens in SQL.
 */
export class DatabaseTokenRepository {
  private readonly query: () => QueryBuilder

  private readonly table: string

  private readonly hashKey: string

  private readonly expiresMinutes: number

  private readonly throttleSeconds: number

  /**
   * @param query - Query builder factory.
   * @param table - `password_resets` table.
   * @param hashKey - HMAC secret for token hashing at rest.
   * @param expiresMinutes - Row lifetime.
   * @param throttleSeconds - Minimum spacing between emails per user.
   */
  public constructor(
    query: () => QueryBuilder,
    table: string,
    hashKey: string,
    expiresMinutes: number,
    throttleSeconds: number,
  ) {
    this.query = query
    this.table = table
    this.hashKey = hashKey
    this.expiresMinutes = expiresMinutes
    this.throttleSeconds = throttleSeconds
  }

  /**
   * Creates a fresh token row and returns the plaintext token for emailing.
   */
  public async create(user: CanResetPassword): Promise<string> {
    const email = user.getEmailForPasswordReset()
    await this.query().table(this.table).where('email', email).delete()
    const plain = randomBytes(32).toString('hex')
    const hashed = hashToken(plain, this.hashKey)
    // QueryBuilder.insert(single) assumes an `id` column on Postgres (`returning "id"`).
    // `password_resets` is keyed by email (no surrogate `id`), so use a one-row bulk insert.
    await this.query()
      .table(this.table)
      .insert([{ email, token: hashed, created_at: new Date() }])
    return plain
  }

  /**
   * @returns True when the plaintext token matches a non-expired row.
   */
  public async exists(user: CanResetPassword, token: string): Promise<boolean> {
    const email = user.getEmailForPasswordReset()
    const row = await this.query()
      .table(this.table)
      .where('email', email)
      .first<{ token: string; created_at: Date | string }>()
    if (row === null) {
      return false
    }
    const created = row.created_at instanceof Date ? row.created_at : new Date(row.created_at)
    if (Date.now() - created.getTime() > this.expiresMinutes * 60 * 1000) {
      return false
    }
    return secureCompare(row.token, hashToken(token, this.hashKey))
  }

  /**
   * @returns True when a token was created within the throttle window.
   */
  public async recentlyCreatedToken(user: CanResetPassword): Promise<boolean> {
    const email = user.getEmailForPasswordReset()
    const row = await this.query()
      .table(this.table)
      .where('email', email)
      .first<{ created_at: Date | string }>()
    if (row === null) {
      return false
    }
    const created = row.created_at instanceof Date ? row.created_at : new Date(row.created_at)
    return Date.now() - created.getTime() < this.throttleSeconds * 1000
  }

  /**
   * Deletes stored tokens for the user email.
   */
  public async delete(user: CanResetPassword): Promise<void> {
    await this.query().table(this.table).where('email', user.getEmailForPasswordReset()).delete()
  }

  /**
   * Deletes expired rows (best-effort cleanup).
   */
  public async deleteExpired(): Promise<void> {
    const cutoff = new Date(Date.now() - this.expiresMinutes * 60 * 1000)
    await this.query().table(this.table).where('created_at', '<', cutoff).delete()
  }
}

function hashToken(token: string, key: string): string {
  return createHmac('sha256', key).update(token).digest('hex')
}
