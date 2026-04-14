/**
 * Parses a raw `Cookie` header into a key/value map (first occurrence wins).
 *
 * @param header - Value of the `Cookie` header.
 * @returns Decoded cookie map.
 */
export function parseCookies(header: string | undefined): Record<string, string> {
  if (header === undefined || header.trim().length === 0) {
    return {}
  }
  const out: Record<string, string> = {}
  for (const part of header.split(';')) {
    const trimmed = part.trim()
    if (trimmed.length === 0) {
      continue
    }
    const eq = trimmed.indexOf('=')
    if (eq <= 0) {
      continue
    }
    const name = trimmed.slice(0, eq).trim()
    const value = decodeURIComponent(trimmed.slice(eq + 1).trim())
    if (!(name in out)) {
      out[name] = value
    }
  }
  return out
}
