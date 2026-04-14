/**
 * Password reset token table metadata for migrations.
 */
export class PasswordResetTableMigration {
  /** Logical table name. */
  public static readonly table = 'password_resets'

  /**
   * Expected columns.
   */
  public static readonly columns = ['email', 'token', 'created_at'] as const
}
