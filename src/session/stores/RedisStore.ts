import type { Redis } from 'ioredis'

import type { SessionStore } from '../../contracts/SessionStore.js'

/**
 * Redis-backed session store with TTL aligned to session lifetime.
 */
export class RedisStore implements SessionStore {
  private readonly redis: Redis

  private readonly prefix: string

  private ttlSeconds: number

  /**
   * @param redis - Shared Redis connection.
   * @param prefix - Key prefix.
   * @param lifetimeMinutes - Session lifetime used as TTL.
   */
  public constructor(redis: Redis, prefix: string, lifetimeMinutes: number) {
    this.redis = redis
    this.prefix = prefix
    this.ttlSeconds = Math.max(60, lifetimeMinutes * 60)
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
    /* connection owned by caller */
  }

  /**
   * @inheritdoc
   */
  public async read(sessionId: string): Promise<string> {
    const v = await this.redis.get(this.key(sessionId))
    return v ?? ''
  }

  /**
   * @inheritdoc
   */
  public async write(sessionId: string, data: string): Promise<void> {
    await this.redis.setex(this.key(sessionId), this.ttlSeconds, data)
  }

  /**
   * @inheritdoc
   */
  public async destroy(sessionId: string): Promise<void> {
    await this.redis.del(this.key(sessionId))
  }

  /**
   * @inheritdoc
   */
  public async gc(_maxLifetime: number): Promise<number> {
    /* Redis TTL handles expiry */
    return 0
  }

  private key(sessionId: string): string {
    return `${this.prefix}${sessionId}`
  }
}
