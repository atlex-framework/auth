import type { Authenticatable } from './Authenticatable.js'

/**
 * Guard capability for HTTP Basic authentication.
 */
export interface SupportsBasicAuth {
  /**
   * Parses `Authorization: Basic`, attempts login, challenges with 401 on failure.
   *
   * @param field - Credential field used for lookup (default `email`).
   * @param extraConditions - Extra fields merged into credential bag.
   */
  basic(field?: string, extraConditions?: Record<string, unknown>): Promise<void>

  /**
   * Stateless basic auth: validates credentials without persisting session state.
   *
   * @param field - Credential field used for lookup.
   * @param extraConditions - Extra fields merged into credential bag.
   */
  onceBasic(field?: string, extraConditions?: Record<string, unknown>): Promise<void>

  /**
   * @returns Authenticated user after successful basic auth.
   */
  user(): Promise<Authenticatable | null>
}
