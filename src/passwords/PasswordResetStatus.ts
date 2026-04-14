/**
 * Outcome codes for password reset flows.
 */
export const PasswordResetStatus = {
  RESET_LINK_SENT: 'passwords.sent',
  PASSWORD_RESET: 'passwords.reset',
  INVALID_USER: 'passwords.user',
  INVALID_TOKEN: 'passwords.token',
  RESET_THROTTLED: 'passwords.throttled',
} as const

export type PasswordResetStatus = (typeof PasswordResetStatus)[keyof typeof PasswordResetStatus]
