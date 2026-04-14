import type { Authenticatable } from './Authenticatable.js'

/**
 * Retrieves and validates users for guards.
 */
export interface UserProvider {
  /**
   * @param id - Primary key.
   * @returns User or null.
   */
  retrieveById(id: string | number): Promise<Authenticatable | null>

  /**
   * @param id - Primary key.
   * @param token - Plain remember token.
   * @returns User or null.
   */
  retrieveByToken(id: string | number, token: string): Promise<Authenticatable | null>

  /**
   * @param user - User whose remember token should be updated.
   * @param token - New hashed/plain token depending on provider implementation.
   */
  updateRememberToken(user: Authenticatable, token: string): Promise<void>

  /**
   * @param credentials - Lookup fields (e.g. email).
   * @returns Matching user or null.
   */
  retrieveByCredentials(credentials: Record<string, unknown>): Promise<Authenticatable | null>

  /**
   * @param user - Candidate user.
   * @param credentials - Credential bag including plaintext password.
   * @returns True when password matches.
   */
  validateCredentials(user: Authenticatable, credentials: Record<string, unknown>): Promise<boolean>
}
