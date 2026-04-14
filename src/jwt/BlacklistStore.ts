/**
 * Key/value store used by {@link JwtBlacklist} (Redis, memory, or DB adapter).
 */
export interface BlacklistStore {
  /**
   * @param key - JWT `jti` (or prefixed key).
   * @param ttlSeconds - Time-to-live in seconds.
   */
  set(key: string, ttlSeconds: number): Promise<void>

  /**
   * @param key - JWT `jti`.
   * @returns True when the token is blacklisted.
   */
  has(key: string): Promise<boolean>

  /**
   * @param key - JWT `jti`.
   */
  delete(key: string): Promise<void>

  /**
   * Removes every blacklist entry (admin / tests).
   */
  flush(): Promise<void>
}
