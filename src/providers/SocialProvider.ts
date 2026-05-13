/**
 * Normalized user profile returned by a social identity provider after token verification.
 */
export interface SocialUser {
  /**
   * Provider key, such as `google` or `apple`.
   */
  readonly provider: string

  /**
   * Provider-specific subject identifier in a provider-agnostic field.
   */
  readonly providerId: string

  /**
   * Verified or provider-reported email address.
   */
  readonly email: string

  /**
   * Whether the provider reports the email address as verified.
   */
  readonly emailVerified: boolean

  /**
   * Display name when provided by the identity provider.
   */
  readonly name: string | null

  /**
   * Avatar URL when provided by the identity provider.
   */
  readonly avatarUrl: string | null

  /**
   * Raw provider payload for application-specific fields.
   */
  readonly raw: Record<string, unknown>
}

/**
 * Normalized Google user profile returned after ID-token verification.
 */
export interface GoogleSocialUser extends SocialUser {
  /**
   * Google provider discriminator.
   */
  readonly provider: 'google'

  /**
   * Google's `sub` claim, mirrored for Google-specific application fields.
   */
  readonly googleId: string
}

/**
 * Contract implemented by social identity providers that verify provider-issued tokens.
 */
export interface SocialProvider<TSocialUser extends SocialUser = SocialUser> {
  /**
   * @param token - Provider-issued token to verify.
   * @returns A normalized social user profile.
   */
  verify(token: string): Promise<TSocialUser>
}
