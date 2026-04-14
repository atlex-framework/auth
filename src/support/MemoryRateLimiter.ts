/**
 * Simple in-memory sliding-window rate limiter for login throttling.
 */
export class MemoryRateLimiter {
  private readonly attempts = new Map<string, { count: number; resetAt: number }>()

  /**
   * @param key - Unique throttle key (e.g. IP + email).
   * @param maxAttempts - Maximum attempts allowed in the window.
   * @returns True when the key is locked out.
   */
  public tooManyAttempts(key: string, maxAttempts: number): boolean {
    const row = this.attempts.get(key)
    if (row === undefined) {
      return false
    }
    if (Date.now() >= row.resetAt) {
      this.attempts.delete(key)
      return false
    }
    return row.count >= maxAttempts
  }

  /**
   * @param key - Throttle key.
   * @param decaySeconds - Window length in seconds.
   */
  public hit(key: string, decaySeconds: number): void {
    const now = Date.now()
    const row = this.attempts.get(key)
    if (row === undefined || now >= row.resetAt) {
      this.attempts.set(key, { count: 1, resetAt: now + decaySeconds * 1000 })
      return
    }
    row.count += 1
  }

  /**
   * Clears attempts for a key after successful login.
   *
   * @param key - Throttle key.
   */
  public clear(key: string): void {
    this.attempts.delete(key)
  }

  /**
   * @param key - Throttle key.
   * @returns Seconds until retry, or 0 when not locked.
   */
  public availableIn(key: string): number {
    const row = this.attempts.get(key)
    if (row === undefined) {
      return 0
    }
    const ms = row.resetAt - Date.now()
    return ms > 0 ? Math.ceil(ms / 1000) : 0
  }
}
