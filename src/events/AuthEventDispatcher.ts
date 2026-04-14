import type { AtlexEvent } from '@atlex/core'

/**
 * Dispatches auth lifecycle events to the application bus.
 */
export type AuthEventDispatcher = (event: AtlexEvent) => void | Promise<void>
