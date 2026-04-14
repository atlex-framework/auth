import { AuthorizationError } from '../errors/AuthorizationError.js'

/**
 * Structured result of an authorization check (closure, policy, or gate).
 */
export class AuthorizationResponse {
  private readonly _allowed: boolean

  private readonly _message?: string

  private readonly _code?: number

  private constructor(allowed: boolean, message?: string, code?: number) {
    this._allowed = allowed
    this._message = message
    this._code = code
  }

  /**
   * @param message - Optional success message.
   * @returns Allowed response.
   */
  public static allow(message?: string): AuthorizationResponse {
    return new AuthorizationResponse(true, message)
  }

  /**
   * @param message - Denial message for clients.
   * @param code - Optional HTTP-style code.
   * @returns Denied response.
   */
  public static deny(message?: string, code?: number): AuthorizationResponse {
    return new AuthorizationResponse(false, message, code)
  }

  /**
   * @returns True when the ability is granted.
   */
  public allowed(): boolean {
    return this._allowed
  }

  /**
   * @returns True when the ability is denied.
   */
  public denied(): boolean {
    return !this._allowed
  }

  /**
   * @returns Optional human-readable message.
   */
  public message(): string | undefined {
    return this._message
  }

  /**
   * @returns Optional custom code supplied with {@link AuthorizationResponse.deny}.
   */
  public code(): number | undefined {
    return this._code
  }

  /**
   * Throws {@link AuthorizationError} when denied.
   */
  public authorize(): void {
    if (this._allowed) {
      return
    }
    throw new AuthorizationError(this._message ?? 'Forbidden', this)
  }
}
