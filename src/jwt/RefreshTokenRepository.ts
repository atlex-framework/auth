import { randomUUID } from 'node:crypto'

import type { QueryBuilder } from '@atlex/orm'

import type { RefreshTokenRecord } from './RefreshTokenRecord.js'

type MemoryRow = RefreshTokenRecord

/**
 * Stores refresh-token metadata for rotation, reuse detection, and revocation.
 */
export class RefreshTokenRepository {
  private readonly mode: 'memory' | 'database'

  private readonly memory = new Map<string, MemoryRow>()

  private readonly table?: string

  private readonly query?: () => QueryBuilder

  /**
   * @param options - `memory` for tests, or `database` with a query factory.
   */
  public constructor(
    options:
      | { readonly mode: 'memory' }
      | { readonly mode: 'database'; readonly table: string; readonly query: () => QueryBuilder },
  ) {
    this.mode = options.mode
    if (options.mode === 'database') {
      this.table = options.table
      this.query = options.query
    }
  }

  /**
   * Persists a refresh token row.
   *
   * @param userId - Owner id.
   * @param familyId - Token family id.
   * @param jti - JWT id claim.
   * @param expiresAt - Absolute expiry instant.
   */
  public async create(
    userId: string | number,
    familyId: string,
    jti: string,
    expiresAt: Date,
  ): Promise<void> {
    const createdAt = new Date()
    const row: RefreshTokenRecord = {
      jti,
      userId,
      familyId,
      isRevoked: false,
      expiresAt,
      createdAt,
    }
    if (this.mode === 'memory') {
      this.memory.set(jti, row)
      return
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    // QueryBuilder.insert(single) assumes an `id` column on Postgres (`returning "id"`).
    // Refresh tokens use `jti` as the primary key, so insert as a single-row bulk insert.
    await qb.table(this.table).insert([
      {
        jti,
        user_id: userId,
        family_id: familyId,
        is_revoked: 0,
        expires_at: expiresAt,
        created_at: createdAt,
      },
    ])
  }

  /**
   * @param jti - JWT id.
   * @returns Row or null.
   */
  public async find(jti: string): Promise<RefreshTokenRecord | null> {
    if (this.mode === 'memory') {
      return this.memory.get(jti) ?? null
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    const row = await qb.table(this.table).where('jti', jti).first<{
      jti: string
      user_id: string | number
      family_id: string
      is_revoked: number | boolean
      expires_at: Date | string
      created_at: Date | string
    }>()
    if (row === undefined || row === null) {
      return null
    }
    return mapDbRow(row)
  }

  /**
   * Marks a single refresh token as revoked.
   *
   * @param jti - JWT id.
   */
  public async revoke(jti: string): Promise<void> {
    if (this.mode === 'memory') {
      const row = this.memory.get(jti)
      if (row !== undefined) {
        this.memory.set(jti, { ...row, isRevoked: true })
      }
      return
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    await qb.table(this.table).where('jti', jti).update({ is_revoked: 1 })
  }

  /**
   * Revokes every token in a rotation family.
   *
   * @param familyId - Family UUID.
   */
  public async revokeFamily(familyId: string): Promise<void> {
    if (this.mode === 'memory') {
      for (const [key, row] of this.memory) {
        if (row.familyId === familyId) {
          this.memory.set(key, { ...row, isRevoked: true })
        }
      }
      return
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    await qb.table(this.table).where('family_id', familyId).update({ is_revoked: 1 })
  }

  /**
   * Revokes all refresh tokens owned by a user.
   *
   * @param userId - Owner id.
   */
  public async revokeAllForUser(userId: string | number): Promise<void> {
    if (this.mode === 'memory') {
      for (const [key, row] of this.memory) {
        if (row.userId === userId) {
          this.memory.set(key, { ...row, isRevoked: true })
        }
      }
      return
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    await qb.table(this.table).where('user_id', userId).update({ is_revoked: 1 })
  }

  /**
   * @param jti - JWT id.
   * @returns True when revoked or missing.
   */
  public async isRevoked(jti: string): Promise<boolean> {
    const row = await this.find(jti)
    return row === null || row.isRevoked
  }

  /**
   * Deletes expired rows.
   *
   * @returns Number of deleted rows.
   */
  public async deleteExpired(): Promise<number> {
    const now = new Date()
    if (this.mode === 'memory') {
      let n = 0
      for (const [k, row] of this.memory) {
        if (row.expiresAt.getTime() <= now.getTime()) {
          this.memory.delete(k)
          n += 1
        }
      }
      return n
    }
    const qb = this.query?.()
    if (qb === undefined || this.table === undefined) {
      throw new Error('RefreshTokenRepository: database mode requires query factory.')
    }
    return await qb.table(this.table).where('expires_at', '<', now).delete()
  }

  /**
   * @returns New cryptographically random family id.
   */
  public static newFamilyId(): string {
    return randomUUID()
  }
}

function mapDbRow(row: {
  jti: string
  user_id: string | number
  family_id: string
  is_revoked: number | boolean
  expires_at: Date | string
  created_at: Date | string
}): RefreshTokenRecord {
  return {
    jti: row.jti,
    userId: row.user_id,
    familyId: row.family_id,
    isRevoked: row.is_revoked === true || row.is_revoked === 1,
    expiresAt: row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at),
    createdAt: row.created_at instanceof Date ? row.created_at : new Date(row.created_at),
  }
}
