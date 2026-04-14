import type { Authenticatable } from './Authenticatable.js'
import type { Guard } from './Guard.js'

/**
 * Guard that can persist authentication state (session / remember-me).
 */
export interface StatefulGuard extends Guard {
  /**
   * @param credentials - Credential bag (e.g. email + password).
   * @param remember - When true, issue a long-lived remember cookie (session guard).
   * @returns True on success.
   */
  attempt(credentials: Record<string, unknown>, remember?: boolean): Promise<boolean>

  /**
   * @param user - User to log in.
   * @param remember - Remember-me flag for session guard.
   */
  login(user: Authenticatable, remember?: boolean): Promise<void>

  /**
   * @param id - User primary key.
   * @param remember - Remember-me flag.
   * @returns Loaded user or false when missing.
   */
  loginUsingId(id: string | number, remember?: boolean): Promise<Authenticatable | false>

  /**
   * Logs the current user out and clears persisted state.
   */
  logout(): Promise<void>

  /**
   * @returns True when the current user was authenticated via remember cookie.
   */
  viaRemember(): boolean
}
