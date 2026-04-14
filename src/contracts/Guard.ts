import type { Authenticatable } from './Authenticatable.js'

/**
 * Stateless authentication guard contract.
 */
export interface Guard {
  /**
   * @returns True when a user is authenticated for this guard.
   */
  check(): Promise<boolean>

  /**
   * @returns True when no user is authenticated.
   */
  guest(): Promise<boolean>

  /**
   * @returns The authenticated user, if any.
   */
  user(): Promise<Authenticatable | null>

  /**
   * @returns Authenticated user id, if any.
   */
  id(): Promise<string | number | null>

  /**
   * @param credentials - Arbitrary credential bag (e.g. email + password).
   * @returns True when credentials are valid without persisting a session.
   */
  validate(credentials: Record<string, unknown>): Promise<boolean>

  /**
   * @returns True when a user has been resolved and cached on this guard instance.
   */
  hasUser(): boolean

  /**
   * @param user - User to treat as authenticated for the remainder of the request.
   */
  setUser(user: Authenticatable): void
}
