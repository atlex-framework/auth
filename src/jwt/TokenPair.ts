/**
 * OAuth2-style access + refresh token bundle returned to API clients.
 */
export interface TokenPair {
  readonly accessToken: string
  readonly refreshToken: string
  readonly tokenType: 'Bearer'
  readonly expiresIn: number
  readonly expiresAt: Date
}
