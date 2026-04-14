import type { Redis } from 'ioredis'

import type { BlacklistStore } from './BlacklistStore.js'

/**
 * Redis-backed JWT blacklist using TTL keys.
 */
export class RedisBlacklistStore implements BlacklistStore {
  private readonly redis: Redis

  private readonly prefix: string

  /**
   * @param redis - Shared ioredis client.
   * @param prefix - Key prefix (e.g. `atlex_jwt_bl:`).
   */
  public constructor(redis: Redis, prefix: string) {
    this.redis = redis
    this.prefix = prefix
  }

  /**
   * @inheritdoc
   */
  public async set(key: string, ttlSeconds: number): Promise<void> {
    await this.redis.setex(`${this.prefix}${key}`, ttlSeconds, '1')
  }

  /**
   * @inheritdoc
   */
  public async has(key: string): Promise<boolean> {
    const v = await this.redis.get(`${this.prefix}${key}`)
    return v !== null
  }

  /**
   * @inheritdoc
   */
  public async delete(key: string): Promise<void> {
    await this.redis.del(`${this.prefix}${key}`)
  }

  /**
   * @inheritdoc
   */
  public async flush(): Promise<void> {
    const keys = await this.redis.keys(`${this.prefix}*`)
    if (keys.length > 0) {
      await this.redis.del(...keys)
    }
  }
}
