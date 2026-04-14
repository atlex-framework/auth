/**
 * User contract for email verification.
 */
export interface MustVerifyEmail {
  /**
   * @returns True when the email is already verified.
   */
  hasVerifiedEmail(): boolean

  /**
   * @returns True when verification was persisted.
   */
  markEmailAsVerified(): Promise<boolean>

  /**
   * Dispatches the verification email to the user.
   */
  sendEmailVerificationNotification(): Promise<void>

  /**
   * @returns Email address that must match signed verification URLs.
   */
  getEmailForVerification(): string
}
