import type { Redis } from 'ioredis'

import type { AuthConfig } from '../config/AuthConfig.js'
import type { SessionStore } from '../contracts/SessionStore.js'

import { Session } from './Session.js'
import { CookieStore } from './stores/CookieStore.js'
import { DatabaseStore } from './stores/DatabaseStore.js'
import { FileStore } from './stores/FileStore.js'
import { NullStore } from './stores/NullStore.js'
import { RedisStore } from './stores/RedisStore.js'

interface SessionFactoryDeps {
  readonly redis?: Redis
  readonly query?: () => import('@atlex/orm').QueryBuilder
}

/**
 * Builds {@link SessionStore} + {@link Session} instances from {@link AuthConfig}.
 */
export class SessionManager {
  private readonly config: AuthConfig['session']

  private readonly deps: SessionFactoryDeps

  private sharedStore: SessionStore | null = null

  /**
   * @param config - Session section of {@link AuthConfig}.
   * @param deps - Optional Redis client / query factory for database/redis drivers.
   */
  public constructor(config: AuthConfig['session'], deps: SessionFactoryDeps = {}) {
    this.config = config
    this.deps = deps
  }

  /**
   * @returns A store matching {@link AuthConfig.session.driver}.
   */
  public store(): SessionStore {
    if (this.sharedStore !== null) {
      return this.sharedStore
    }
    const driver = this.config.driver
    if (driver === 'null') {
      this.sharedStore = new NullStore()
      return this.sharedStore
    }
    if (driver === 'file') {
      this.sharedStore = new FileStore()
      return this.sharedStore
    }
    if (driver === 'database') {
      const q = this.deps.query
      if (q === undefined) {
        throw new Error('SessionManager: database driver requires a QueryBuilder factory.')
      }
      this.sharedStore = new DatabaseStore(q, this.config.table)
      return this.sharedStore
    }
    if (driver === 'redis') {
      const redis = this.deps.redis
      if (redis === undefined) {
        throw new Error('SessionManager: redis driver requires an ioredis client.')
      }
      this.sharedStore = new RedisStore(redis, this.config.prefix, this.config.lifetime)
      return this.sharedStore
    }
    if (driver === 'cookie') {
      const key = this.config.encryptionKey ?? ''
      if (key.length === 0) {
        throw new Error(
          'SessionManager: cookie driver requires session.encryptionKey (or auth.appKey).',
        )
      }
      this.sharedStore = new CookieStore(key, this.config.encrypt)
      return this.sharedStore
    }
    throw new Error(`SessionManager: unsupported session driver "${String(driver)}".`)
  }

  /**
   * Opens file-based stores with the configured `files` path.
   */
  public async openStore(): Promise<void> {
    const st = this.store()
    await st.open(this.config.files, this.config.cookie)
  }

  /**
   * @returns New session instance bound to the shared store.
   */
  public session(): Session {
    return new Session(this.store(), this.config.cookie)
  }

  /**
   * When using the cookie store, forwards the raw `Cookie` header before reads.
   *
   * @param cookieHeader - `Cookie` header from the request.
   */
  public primeCookieStore(cookieHeader: string | undefined): void {
    const st = this.store()
    if (st instanceof CookieStore) {
      st.setIncoming(cookieHeader, this.config.cookie)
    }
  }

  /**
   * When using the cookie store, returns the serialized cookie payload after writes.
   */
  public cookieStorePayload(): string | null {
    const st = this.store()
    if (st instanceof CookieStore) {
      const v = st.getOutgoingCookieValue()
      return v.length > 0 ? v : null
    }
    return null
  }
}
