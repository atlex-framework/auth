/**
 * Persistence backend for {@link Session}.
 */
export interface SessionStore {
  /**
   * @param savePath - File driver root path (unused for non-file drivers).
   * @param sessionName - Logical session cookie/name prefix segment.
   */
  open(savePath: string, sessionName: string): Promise<void>

  /**
   * Releases resources for this store handle.
   */
  close(): Promise<void>

  /**
   * @param sessionId - Session identifier.
   * @returns Serialized session payload (often JSON); empty string when missing.
   */
  read(sessionId: string): Promise<string>

  /**
   * @param sessionId - Session identifier.
   * @param data - Serialized payload to persist.
   */
  write(sessionId: string, data: string): Promise<void>

  /**
   * @param sessionId - Session identifier.
   */
  destroy(sessionId: string): Promise<void>

  /**
   * @param maxLifetime - Oldest acceptable last-activity age in seconds.
   * @returns Number of sessions removed.
   */
  gc(maxLifetime: number): Promise<number>
}
