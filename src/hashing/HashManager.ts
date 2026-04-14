import type { AuthConfig } from '../config/AuthConfig.js'

import { Argon2Hasher } from './Argon2Hasher.js'
import { BcryptHasher } from './BcryptHasher.js'
import type { Hasher } from './Hasher.js'
import { ScryptHasher } from './ScryptHasher.js'

export interface HashInfo {
  readonly driver: string
}

/**
 * Factory for bcrypt / argon2 / scrypt hashers driven by config.
 */
export class HashManager {
  private readonly config: AuthConfig['hashing']

  private readonly defaultDriver: string

  private readonly drivers = new Map<string, Hasher>()

  /**
   * @param config - Hashing section from {@link AuthConfig}.
   * @param defaultDriver - Key such as `bcrypt`, `argon2`, or `scrypt`.
   */
  public constructor(config: AuthConfig['hashing'], defaultDriver: string) {
    this.config = config
    this.defaultDriver = defaultDriver
  }

  /**
   * @param name - Driver key; defaults to configured default.
   * @returns Hasher implementation.
   */
  public driver(name?: string): Hasher {
    const key = name ?? this.defaultDriver
    const cached = this.drivers.get(key)
    if (cached !== undefined) {
      return cached
    }
    const created = this.createDriver(key)
    this.drivers.set(key, created)
    return created
  }

  /**
   * @inheritdoc Hasher.make — uses default driver.
   */
  public async make(value: string): Promise<string> {
    return await this.driver().make(value)
  }

  /**
   * @inheritdoc Hasher.check — uses default driver.
   */
  public async check(value: string, hashedValue: string): Promise<boolean> {
    return await this.driver().check(value, hashedValue)
  }

  /**
   * @inheritdoc Hasher.needsRehash — uses default driver.
   */
  public needsRehash(hashedValue: string): boolean {
    return this.driver().needsRehash(hashedValue)
  }

  /**
   * @param hashedValue - Stored hash.
   * @returns Minimal metadata for diagnostics.
   */
  public info(hashedValue: string): HashInfo {
    if (hashedValue.startsWith('scrypt$')) {
      return { driver: 'scrypt' }
    }
    if (hashedValue.startsWith('$argon2')) {
      return { driver: 'argon2' }
    }
    return { driver: 'bcrypt' }
  }

  private createDriver(key: string): Hasher {
    if (key === 'bcrypt') {
      return new BcryptHasher(this.config.bcrypt.rounds)
    }
    if (key === 'argon2') {
      return new Argon2Hasher(this.config.argon2)
    }
    if (key === 'scrypt') {
      return new ScryptHasher(this.config.scrypt)
    }
    throw new Error(`HashManager: unknown hashing driver "${key}".`)
  }
}
