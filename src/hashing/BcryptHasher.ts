import bcrypt from 'bcryptjs'

import type { Hasher } from './Hasher.js'

/**
 * bcrypt-based password hasher (pure JS via `bcryptjs`).
 */
export class BcryptHasher implements Hasher {
  private readonly rounds: number

  /**
   * @param rounds - bcrypt cost factor.
   */
  public constructor(rounds: number) {
    this.rounds = rounds
  }

  /**
   * @inheritdoc
   */
  public async make(value: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.rounds)
    return await bcrypt.hash(value, salt)
  }

  /**
   * @inheritdoc
   */
  public async check(value: string, hashedValue: string): Promise<boolean> {
    return await bcrypt.compare(value, hashedValue)
  }

  /**
   * @inheritdoc
   */
  public needsRehash(hashedValue: string): boolean {
    const rounds = bcrypt.getRounds(hashedValue)
    return rounds < this.rounds
  }
}
