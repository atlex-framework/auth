/**
 * Session table metadata for migrations (`sessions` driver).
 */
export class SessionTableMigration {
  /** Logical table name. */
  public static readonly table = 'sessions'

  /**
   * Expected columns for the database session driver.
   */
  public static readonly columns = [
    'id',
    'user_id',
    'ip_address',
    'user_agent',
    'payload',
    'last_activity',
  ] as const
}
