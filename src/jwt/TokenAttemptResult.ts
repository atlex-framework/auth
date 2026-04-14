import type { Authenticatable } from '../contracts/Authenticatable.js'

import type { TokenPair } from './TokenPair.js'

/**
 * Successful JWT login payload including the authenticated principal.
 */
export type TokenAttemptResult = TokenPair & { readonly user: Authenticatable }
