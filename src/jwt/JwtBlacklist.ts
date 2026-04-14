import { decodeJwt } from 'jose'

import type { BlacklistStore } from './BlacklistStore.js'

/**
 * Invalidates access tokens by `jti` until natural expiry (+ optional grace period).
 */
export class JwtBlacklist {
  private readonly store: BlacklistStore

  private readonly gracePeriodSeconds: number

  /**
   * @param store - Underlying key/value store.
   * @param gracePeriodSeconds - Extra seconds to keep a blacklisted `jti` after token expiry.
   */
  public constructor(store: BlacklistStore, gracePeriodSeconds: number) {
    this.store = store
    this.gracePeriodSeconds = gracePeriodSeconds
  }

  /**
   * Blacklists a JWT by `jti` until remaining lifetime + grace.
   *
   * @param token - Raw JWT string.
   */
  public async add(token: string): Promise<void> {
    const payload = decodeJwt(token)
    const jti = typeof payload.jti === 'string' ? payload.jti : null
    if (jti === null || jti.length === 0) {
      return
    }
    const exp = typeof payload.exp === 'number' ? payload.exp : Math.floor(Date.now() / 1000) + 60
    const now = Math.floor(Date.now() / 1000)
    const remaining = Math.max(0, exp - now)
    await this.store.set(jti, remaining + this.gracePeriodSeconds)
  }

  /**
   * @param token - Raw JWT string.
   * @returns True when blacklisted.
   */
  public async isBlacklisted(token: string): Promise<boolean> {
    const payload = decodeJwt(token)
    const jti = typeof payload.jti === 'string' ? payload.jti : null
    if (jti === null || jti.length === 0) {
      return false
    }
    return await this.store.has(jti)
  }

  /**
   * Clears all blacklist entries.
   */
  public async flush(): Promise<void> {
    await this.store.flush()
  }
}
