import type { BlacklistStore } from './BlacklistStore.js'

interface Entry {
  expiresAt: number
}

/**
 * In-memory blacklist suitable for tests and single-node deployments.
 */
export class MemoryBlacklistStore implements BlacklistStore {
  private readonly entries = new Map<string, Entry>()

  /**
   * @inheritdoc
   */
  public async set(key: string, ttlSeconds: number): Promise<void> {
    this.entries.set(key, { expiresAt: Date.now() + ttlSeconds * 1000 })
  }

  /**
   * @inheritdoc
   */
  public async has(key: string): Promise<boolean> {
    const row = this.entries.get(key)
    if (row === undefined) {
      return false
    }
    if (Date.now() >= row.expiresAt) {
      this.entries.delete(key)
      return false
    }
    return true
  }

  /**
   * @inheritdoc
   */
  public async delete(key: string): Promise<void> {
    this.entries.delete(key)
  }

  /**
   * @inheritdoc
   */
  public async flush(): Promise<void> {
    this.entries.clear()
  }
}
