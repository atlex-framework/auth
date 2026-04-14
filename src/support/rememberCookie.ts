import { createHmac } from 'node:crypto'

import { secureCompare } from './secureCompare.js'

/**
 * Packs a remember-me cookie payload signed with the application secret.
 *
 * @param userId - Authenticated user id.
 * @param plainToken - Plaintext remember selector.
 * @param secret - UTF-8 signing secret.
 */
export function packRememberCookie(
  userId: string | number,
  plainToken: string,
  secret: string,
): string {
  const body = `${String(userId)}|${plainToken}`
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${Buffer.from(body, 'utf8').toString('base64url')}.${sig}`
}

/**
 * @param value - Cookie value from the client.
 * @param secret - UTF-8 signing secret.
 * @returns Parsed id + plaintext token when the signature is valid.
 */
export function unpackRememberCookie(
  value: string,
  secret: string,
): { userId: string | number; plainToken: string } | null {
  const dot = value.indexOf('.')
  if (dot <= 0) {
    return null
  }
  const blob = value.slice(0, dot)
  const sig = value.slice(dot + 1)
  let body: string
  try {
    body = Buffer.from(blob, 'base64url').toString('utf8')
  } catch {
    return null
  }
  const expected = createHmac('sha256', secret).update(body).digest('base64url')
  if (!secureCompare(expected, sig)) {
    return null
  }
  const pipe = body.indexOf('|')
  if (pipe <= 0) {
    return null
  }
  const idRaw = body.slice(0, pipe)
  const plainToken = body.slice(pipe + 1)
  const asNum = Number(idRaw)
  const userId = Number.isFinite(asNum) && String(asNum) === idRaw ? asNum : idRaw
  return { userId, plainToken }
}
