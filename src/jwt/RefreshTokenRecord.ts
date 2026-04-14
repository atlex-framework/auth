/**
 * Persisted refresh-token metadata for rotation and reuse detection.
 */
export interface RefreshTokenRecord {
  readonly jti: string
  readonly userId: string | number
  readonly familyId: string
  readonly isRevoked: boolean
  readonly expiresAt: Date
  readonly createdAt: Date
}
