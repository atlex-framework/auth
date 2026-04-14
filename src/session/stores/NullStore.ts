import type { SessionStore } from '../../contracts/SessionStore.js'

/**
 * In-memory session store for unit tests and stateless routes (per-session id map).
 */
export class NullStore implements SessionStore {
  private readonly payloads = new Map<string, string>()

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
    /* noop */
  }

  /**
   * @inheritdoc
   */
  public async read(sessionId: string): Promise<string> {
    return this.payloads.get(sessionId) ?? ''
  }

  /**
   * @inheritdoc
   */
  public async write(sessionId: string, data: string): Promise<void> {
    this.payloads.set(sessionId, data)
  }

  /**
   * @inheritdoc
   */
  public async destroy(sessionId: string): Promise<void> {
    this.payloads.delete(sessionId)
  }

  /**
   * @inheritdoc
   */
  public async gc(_maxLifetime: number): Promise<number> {
    return 0
  }
}
