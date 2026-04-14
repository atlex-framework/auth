import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

import type { Hasher } from './Hasher.js'

/**
 * Node.js `crypto.scrypt` password hasher with embedded parameters in the hash string.
 */
export class ScryptHasher implements Hasher {
  private readonly cost: number

  private readonly blockSize: number

  private readonly parallelization: number

  /**
   * @param opts - Scrypt parameters.
   */
  public constructor(opts: { cost: number; blockSize: number; parallelization: number }) {
    this.cost = opts.cost
    this.blockSize = opts.blockSize
    this.parallelization = opts.parallelization
  }

  /**
   * @inheritdoc
   */
  public async make(value: string): Promise<string> {
    const salt = randomBytes(16)
    const derived = await scryptDerive(value, salt, 64, {
      N: this.cost,
      r: this.blockSize,
      p: this.parallelization,
    })
    return [
      'scrypt',
      this.cost,
      this.blockSize,
      this.parallelization,
      salt.toString('base64url'),
      derived.toString('base64url'),
    ].join('$')
  }

  /**
   * @inheritdoc
   */
  public async check(value: string, hashedValue: string): Promise<boolean> {
    const parsed = parseStored(hashedValue)
    if (parsed === null) {
      return false
    }
    try {
      const derived = await scryptDerive(value, parsed.salt, 64, {
        N: parsed.N,
        r: parsed.r,
        p: parsed.p,
      })
      if (derived.length !== parsed.hash.length) {
        return false
      }
      return timingSafeEqual(derived, parsed.hash)
    } catch {
      return false
    }
  }

  /**
   * @inheritdoc
   */
  public needsRehash(hashedValue: string): boolean {
    const parsed = parseStored(hashedValue)
    if (parsed === null) {
      return true
    }
    return (
      parsed.N !== this.cost || parsed.r !== this.blockSize || parsed.p !== this.parallelization
    )
  }
}

function scryptDerive(
  password: string,
  salt: Buffer,
  keylen: number,
  opts: { N: number; r: number; p: number },
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, opts, (err, derivedKey) => {
      if (err !== null) {
        reject(err)
        return
      }
      resolve(derivedKey)
    })
  })
}

function parseStored(hashedValue: string): {
  salt: Buffer
  hash: Buffer
  N: number
  r: number
  p: number
} | null {
  const parts = hashedValue.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    return null
  }
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) {
    return null
  }
  try {
    const salt = Buffer.from(parts[4] ?? '', 'base64url')
    const hash = Buffer.from(parts[5] ?? '', 'base64url')
    return { salt, hash, N, r, p }
  } catch {
    return null
  }
}
