/**
 * Contract for a model that can authenticate against a guard.
 */
export interface Authenticatable {
  /**
   * @returns Primary key attribute name (e.g. `id`).
   */
  getAuthIdentifierName(): string

  /**
   * @returns Primary key value for this user.
   */
  getAuthIdentifier(): string | number

  /**
   * @returns Hashed password for credential checks.
   */
  getAuthPassword(): string

  /**
   * @returns Current remember-token value, if any.
   */
  getRememberToken(): string | null

  /**
   * @param token - New remember token to persist.
   */
  setRememberToken(token: string): void

  /**
   * @returns Remember-token column name on the persistence layer.
   */
  getRememberTokenName(): string
}
