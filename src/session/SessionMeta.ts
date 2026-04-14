/**
 * Internal session envelope persisted by stores (JSON-serialized).
 */
export interface SessionMeta {
  readonly attributes: Record<string, unknown>
  flashNext: Record<string, unknown>
  flashNow: Record<string, unknown>
  csrfToken: string | null
  previousUrl: string | null
}

/**
 * @returns Empty session meta structure.
 */
export function emptySessionMeta(): SessionMeta {
  return {
    attributes: {},
    flashNext: {},
    flashNow: {},
    csrfToken: null,
    previousUrl: null,
  }
}
