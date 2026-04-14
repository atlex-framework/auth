/**
 * Parses human-readable duration strings (`15m`, `7d`, `3600s`) into seconds.
 *
 * @param value - Duration string.
 * @returns Length in whole seconds.
 */
export function parseDurationToSeconds(value: string): number {
  const trimmed = value.trim()
  const match = /^(\d+)\s*([smhd])$/iu.exec(trimmed)
  if (match === null) {
    throw new Error(`Invalid duration string: "${value}"`)
  }
  const amount = Number(match[1])
  const unit = match[2]?.toLowerCase() ?? 's'
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error(`Invalid duration amount in "${value}"`)
  }
  const mult = unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 86400
  return amount * mult
}
