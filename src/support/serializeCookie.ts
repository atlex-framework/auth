import type { AuthConfig } from '../config/AuthConfig.js'

/**
 * Builds a single `Set-Cookie` header value (without splitting attributes).
 *
 * @param name - Cookie name.
 * @param value - Raw cookie value (already encoded if needed).
 * @param cfg - Session cookie defaults from auth config.
 * @param maxAgeSeconds - Optional `Max-Age` in seconds.
 */
export function serializeCookie(
  name: string,
  value: string,
  cfg: AuthConfig['session'],
  maxAgeSeconds?: number,
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${cfg.path}`]
  if (cfg.domain !== null && cfg.domain.length > 0) {
    parts.push(`Domain=${cfg.domain}`)
  }
  const secure = cfg.secure === 'auto' ? process.env.NODE_ENV === 'production' : cfg.secure
  if (secure) {
    parts.push('Secure')
  }
  if (cfg.httpOnly) {
    parts.push('HttpOnly')
  }
  parts.push(`SameSite=${cfg.sameSite}`)
  if (maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${Math.floor(maxAgeSeconds)}`)
  }
  return parts.join('; ')
}
