/**
 * User contract for password reset flows.
 */
export interface CanResetPassword {
  /**
   * @returns Email used to index password reset tokens.
   */
  getEmailForPasswordReset(): string

  /**
   * @param token - Plaintext reset token for the notification URL.
   */
  sendPasswordResetNotification(token: string): Promise<void>
}
