import argon2 from 'argon2'

import type { Hasher } from './Hasher.js'

type Argon2TypeKey = 'argon2i' | 'argon2d' | 'argon2id'

const typeMap: Record<Argon2TypeKey, number> = {
  argon2i: argon2.argon2i,
  argon2d: argon2.argon2d,
  argon2id: argon2.argon2id,
}

/**
 * Argon2 password hasher.
 */
export class Argon2Hasher implements Hasher {
  private readonly options: {
    readonly memoryCost: number
    readonly parallelism: number
    readonly timeCost: number
    readonly type: Argon2TypeKey
  }

  /**
   * @param opts - Argon2 tuning parameters.
   */
  public constructor(opts: { memory: number; threads: number; time: number; type: Argon2TypeKey }) {
    this.options = {
      memoryCost: opts.memory,
      parallelism: opts.threads,
      timeCost: opts.time,
      type: opts.type,
    }
  }

  /**
   * @inheritdoc
   */
  public async make(value: string): Promise<string> {
    return await argon2.hash(value, {
      type: typeMap[this.options.type] as 0 | 1 | 2,
      memoryCost: this.options.memoryCost,
      timeCost: this.options.timeCost,
      parallelism: this.options.parallelism,
    })
  }

  /**
   * @inheritdoc
   */
  public async check(value: string, hashedValue: string): Promise<boolean> {
    try {
      return await argon2.verify(hashedValue, value)
    } catch {
      return false
    }
  }

  /**
   * @inheritdoc
   */
  public needsRehash(hashedValue: string): boolean {
    try {
      return argon2.needsRehash(hashedValue, {
        memoryCost: this.options.memoryCost,
        timeCost: this.options.timeCost,
        parallelism: this.options.parallelism,
      })
    } catch {
      return true
    }
  }
}
