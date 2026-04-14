import { randomBytes, randomUUID } from 'node:crypto'

import type { SessionStore } from '../contracts/SessionStore.js'

import { emptySessionMeta, type SessionMeta } from './SessionMeta.js'

const META_KEY = '__atlex_meta'

/**
 * Mutable HTTP session bound to a {@link SessionStore}.
 */
export class Session {
  private readonly store: SessionStore

  private readonly logicalName: string

  private idValue: string

  private startedFlag = false

  private meta: SessionMeta = emptySessionMeta()

  /**
   * @param store - Persistence backend.
   * @param name - Logical session name (cookie segment / driver hint).
   */
  public constructor(store: SessionStore, name: string) {
    this.store = store
    this.logicalName = name
    this.idValue = randomUUID()
  }

  /**
   * @returns Opaque session identifier.
   */
  public getId(): string {
    return this.idValue
  }

  /**
   * @param id - New session identifier (used after regeneration).
   */
  public setId(id: string): void {
    this.idValue = id
  }

  /**
   * @returns Logical session name provided at construction.
   */
  public getName(): string {
    return this.logicalName
  }

  /**
   * Loads session data from the store.
   *
   * @returns False when the session is new / empty.
   */
  public async start(): Promise<boolean> {
    await this.store.open('', this.logicalName)
    const raw = await this.store.read(this.idValue)
    if (raw.length === 0) {
      this.startedFlag = true
      this.meta = emptySessionMeta()
      return false
    }
    try {
      const parsed = JSON.parse(raw) as unknown
      this.meta = normalizeMeta(parsed)
    } catch {
      this.meta = emptySessionMeta()
    }
    this.startedFlag = true
    return true
  }

  /**
   * Persists the current session payload.
   */
  public async save(): Promise<void> {
    const envelope: Record<string, unknown> = {
      ...this.meta.attributes,
      [META_KEY]: {
        flashNext: this.meta.flashNext,
        flashNow: this.meta.flashNow,
        csrfToken: this.meta.csrfToken,
        previousUrl: this.meta.previousUrl,
      },
    }
    await this.store.write(this.idValue, JSON.stringify(envelope))
  }

  /**
   * Rotates the session id; optionally destroys the previous row.
   *
   * @param destroy - When true, delete the old id from the store.
   * @returns True when migration succeeded.
   */
  public async migrate(destroy = false): Promise<boolean> {
    const previous = this.idValue
    this.idValue = randomUUID()
    if (destroy) {
      await this.store.destroy(previous)
    } else {
      const raw = await this.store.read(previous)
      if (raw.length > 0) {
        await this.store.write(this.idValue, raw)
        await this.store.destroy(previous)
      }
    }
    return true
  }

  /**
   * Clears session data and rotates the identifier.
   */
  public async invalidate(): Promise<boolean> {
    await this.store.destroy(this.idValue)
    this.idValue = randomUUID()
    this.meta = emptySessionMeta()
    this.startedFlag = true
    return true
  }

  /**
   * @returns True after {@link Session.start} completes.
   */
  public isStarted(): boolean {
    return this.startedFlag
  }

  /**
   * @returns Copy of user attributes (excludes internal meta envelope when stored inline).
   */
  public all(): Record<string, unknown> {
    return { ...this.meta.attributes }
  }

  /**
   * @param key - Attribute key.
   */
  public has(key: string): boolean {
    return key in this.meta.attributes || key in this.meta.flashNow
  }

  /**
   * @param key - Attribute key.
   */
  public exists(key: string): boolean {
    return this.has(key)
  }

  /**
   * @param key - Attribute key.
   */
  public missing(key: string): boolean {
    return !this.has(key)
  }

  /**
   * @param key - Attribute key.
   * @param fallback - Value when missing.
   * @returns Stored value or fallback.
   */
  public get<T = unknown>(key: string, fallback?: T): T {
    if (key in this.meta.flashNow) {
      return this.meta.flashNow[key] as T
    }
    if (key in this.meta.attributes) {
      return this.meta.attributes[key] as T
    }
    return fallback as T
  }

  /**
   * @param key - Attribute key.
   * @param value - Serializable value.
   */
  public put(key: string, value: unknown): void {
    this.meta.attributes[key] = value
  }

  /**
   * Appends to an array attribute (creates the array when missing).
   *
   * @param key - Attribute key.
   * @param value - Value to append.
   */
  public push(key: string, value: unknown): void {
    const cur = this.meta.attributes[key]
    if (Array.isArray(cur)) {
      cur.push(value)
      return
    }
    this.meta.attributes[key] = [value]
  }

  /**
   * @param key - Attribute key.
   * @param fallback - Fallback when missing.
   * @returns Removed value or fallback.
   */
  public pull<T = unknown>(key: string, fallback?: T): T {
    if (key in this.meta.flashNow) {
      const v = this.meta.flashNow[key] as T
      delete this.meta.flashNow[key]
      return v
    }
    if (key in this.meta.attributes) {
      const v = this.meta.attributes[key] as T
      delete this.meta.attributes[key]
      return v
    }
    return fallback as T
  }

  /**
   * @param key - Attribute key or list of keys.
   */
  public forget(key: string | string[]): void {
    const keys = Array.isArray(key) ? key : [key]
    for (const k of keys) {
      delete this.meta.attributes[k]
      delete this.meta.flashNow[k]
      delete this.meta.flashNext[k]
    }
  }

  /**
   * Clears user attributes and flash buckets (keeps structural defaults).
   */
  public flush(): void {
    this.meta = {
      ...emptySessionMeta(),
      csrfToken: this.meta.csrfToken,
    }
  }

  /**
   * @param key - Numeric attribute key.
   * @param amount - Delta (default 1).
   * @returns New value.
   */
  public increment(key: string, amount = 1): number {
    const cur = Number(this.meta.attributes[key] ?? 0)
    const next = cur + amount
    this.meta.attributes[key] = next
    return next
  }

  /**
   * @param key - Numeric attribute key.
   * @param amount - Delta (default 1).
   * @returns New value.
   */
  public decrement(key: string, amount = 1): number {
    return this.increment(key, -amount)
  }

  /**
   * Flash data for the next request.
   *
   * @param key - Flash key.
   * @param value - Serializable value.
   */
  public flash(key: string, value: unknown): void {
    this.meta.flashNext[key] = value
  }

  /**
   * Flash data for the current request only.
   *
   * @param key - Flash key.
   * @param value - Serializable value.
   */
  public now(key: string, value: unknown): void {
    this.meta.flashNow[key] = value
  }

  /**
   * Keeps all flash data for an additional request.
   */
  public reflash(): void {
    this.meta.flashNext = { ...this.meta.flashNow, ...this.meta.flashNext }
  }

  /**
   * Keeps only the provided flash keys for another request.
   *
   * @param keys - Keys to persist into the next flash bag.
   */
  public keep(keys: string | string[]): void {
    const list = Array.isArray(keys) ? keys : [keys]
    for (const k of list) {
      if (k in this.meta.flashNow) {
        this.meta.flashNext[k] = this.meta.flashNow[k]
      }
    }
  }

  /**
   * @returns CSRF token (creates one when missing).
   */
  public token(): string {
    if (this.meta.csrfToken === null || this.meta.csrfToken.length === 0) {
      this.meta.csrfToken = randomBytes(32).toString('hex')
    }
    return this.meta.csrfToken
  }

  /**
   * Rotates the CSRF token value.
   */
  public regenerateToken(): void {
    this.meta.csrfToken = randomBytes(32).toString('hex')
  }

  /**
   * @returns Previously stored intended URL, if any.
   */
  public previousUrl(): string | null {
    return this.meta.previousUrl
  }

  /**
   * @param url - URL to remember for redirects.
   */
  public setPreviousUrl(url: string): void {
    this.meta.previousUrl = url
  }

  /**
   * Ages flash data at the beginning of a request (moves `flashNext` from the last response into `flashNow`).
   */
  public ageFlashData(): void {
    this.meta.flashNow = { ...this.meta.flashNext }
    this.meta.flashNext = {}
  }
}

function normalizeMeta(parsed: unknown): SessionMeta {
  if (!isRecord(parsed)) {
    return emptySessionMeta()
  }
  const inner = parsed[META_KEY]
  if (isRecord(inner)) {
    return {
      attributes: omitKey(parsed, META_KEY),
      flashNext: asRecord(inner.flashNext),
      flashNow: asRecord(inner.flashNow),
      csrfToken: typeof inner.csrfToken === 'string' ? inner.csrfToken : null,
      previousUrl: typeof inner.previousUrl === 'string' ? inner.previousUrl : null,
    }
  }
  return {
    attributes: { ...parsed },
    flashNext: {},
    flashNow: {},
    csrfToken: null,
    previousUrl: null,
  }
}

function omitKey(rec: Record<string, unknown>, key: string): Record<string, unknown> {
  const { [key]: _removed, ...rest } = rec
  return rest
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function asRecord(v: unknown): Record<string, unknown> {
  return isRecord(v) ? { ...v } : {}
}
