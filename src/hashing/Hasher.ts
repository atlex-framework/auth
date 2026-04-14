/**
 * Password hashing driver contract.
 */
export interface Hasher {
  /**
   * @param value - Plain secret.
   * @returns Stored hash representation.
   */
  make(value: string): Promise<string>

  /**
   * @param value - Plain secret.
   * @param hashedValue - Previously stored hash.
   * @returns True when the secret matches.
   */
  check(value: string, hashedValue: string): Promise<boolean>

  /**
   * @param hashedValue - Stored hash.
   * @returns True when the hash should be regenerated (e.g. cost changed).
   */
  needsRehash(hashedValue: string): boolean
}
