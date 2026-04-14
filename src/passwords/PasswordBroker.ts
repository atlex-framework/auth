import type { AuthConfig } from '../config/AuthConfig.js'
import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { CanResetPassword } from '../contracts/CanResetPassword.js'
import type { UserProvider } from '../contracts/UserProvider.js'
import type { AuthEventDispatcher } from '../events/AuthEventDispatcher.js'
import { PasswordReset } from '../events/PasswordReset.js'
import { PasswordResetLinkSent } from '../events/PasswordResetLinkSent.js'

import { type DatabaseTokenRepository } from './DatabaseTokenRepository.js'
import { PasswordResetStatus } from './PasswordResetStatus.js'

function isCanResetPassword(user: Authenticatable): user is Authenticatable & CanResetPassword {
  const u = user as unknown as Partial<CanResetPassword>
  return (
    typeof u.getEmailForPasswordReset === 'function' &&
    typeof u.sendPasswordResetNotification === 'function'
  )
}

type PasswordSlice = AuthConfig['passwords'][string]

/**
 * Orchestrates password reset token lifecycle and user notifications.
 */
export class PasswordBroker {
  private readonly tokens: DatabaseTokenRepository

  private readonly provider: UserProvider

  private readonly dispatch: AuthEventDispatcher

  /**
   * @param tokens - Token persistence.
   * @param provider - User lookup.
   * @param config - Named passwords config slice.
   * @param dispatch - Event dispatcher.
   */
  public constructor(
    tokens: DatabaseTokenRepository,
    provider: UserProvider,
    _config: PasswordSlice,
    dispatch: AuthEventDispatcher,
  ) {
    this.tokens = tokens
    this.provider = provider
    this.dispatch = dispatch
  }

  /**
   * Sends a reset link email when the user exists and is not throttled.
   */
  public async sendResetLink(
    credentials: Record<string, unknown>,
  ): Promise<
    | typeof PasswordResetStatus.RESET_LINK_SENT
    | typeof PasswordResetStatus.INVALID_USER
    | typeof PasswordResetStatus.RESET_THROTTLED
  > {
    const user = await this.getUser(credentials)
    if (user === null || !isCanResetPassword(user)) {
      return PasswordResetStatus.INVALID_USER
    }
    if (await this.tokens.recentlyCreatedToken(user)) {
      return PasswordResetStatus.RESET_THROTTLED
    }
    const token = await this.tokens.create(user)
    await user.sendPasswordResetNotification(token)
    void this.dispatch(new PasswordResetLinkSent({ user }))
    return PasswordResetStatus.RESET_LINK_SENT
  }

  /**
   * Validates a token and lets the caller persist the new password.
   */
  public async reset(
    credentials: Record<string, unknown>,
    callback: (user: Authenticatable, password: string) => Promise<void>,
  ): Promise<
    | typeof PasswordResetStatus.PASSWORD_RESET
    | typeof PasswordResetStatus.INVALID_USER
    | typeof PasswordResetStatus.INVALID_TOKEN
  > {
    const password = credentials.password
    const token = credentials.token
    if (typeof password !== 'string' || typeof token !== 'string') {
      return PasswordResetStatus.INVALID_TOKEN
    }
    const user = await this.getUser(credentials)
    if (user === null || !isCanResetPassword(user)) {
      return PasswordResetStatus.INVALID_USER
    }
    if (!(await this.tokens.exists(user, token))) {
      return PasswordResetStatus.INVALID_TOKEN
    }
    await callback(user, password)
    await this.tokens.delete(user)
    void this.dispatch(new PasswordReset({ user }))
    return PasswordResetStatus.PASSWORD_RESET
  }

  /**
   * @returns Plaintext token for testing or custom mailers.
   */
  public async createToken(user: Authenticatable & CanResetPassword): Promise<string> {
    return await this.tokens.create(user)
  }

  /**
   * Deletes any outstanding reset token rows for the user.
   */
  public async deleteToken(user: Authenticatable & CanResetPassword): Promise<void> {
    await this.tokens.delete(user)
  }

  /**
   * @returns True when the plaintext token matches the stored hash.
   */
  public async tokenExists(
    user: Authenticatable & CanResetPassword,
    token: string,
  ): Promise<boolean> {
    return await this.tokens.exists(user, token)
  }

  /**
   * Resolves a user from credentials (typically `{ email }`).
   */
  public async getUser(credentials: Record<string, unknown>): Promise<Authenticatable | null> {
    return await this.provider.retrieveByCredentials(credentials)
  }
}
