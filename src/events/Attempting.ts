import { AtlexEvent } from '@atlex/core'

/**
 * Fired immediately before validating credentials.
 */
export class Attempting extends AtlexEvent {
  /**
   * @param payload - Guard name and credential context.
   */
  public constructor(
    public readonly payload: {
      readonly guard: string
      readonly credentials: Record<string, unknown>
      readonly remember: boolean
    },
  ) {
    super()
  }
}
