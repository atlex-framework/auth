import { timingSafeEqual } from 'node:crypto'

/**
 * Constant-time string comparison for secrets and tokens.
 *
 * @param a - Left operand.
 * @param b - Right operand.
 * @returns True when both strings are identical.
 */
export function secureCompare(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ba.length !== bb.length) {
    return false
  }
  return timingSafeEqual(ba, bb)
}
