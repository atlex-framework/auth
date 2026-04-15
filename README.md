# @atlex/auth

> Complete authentication system with JWT, sessions, guards, authorization, password hashing, and email verification for Express + Node.js applications.

[![npm version](https://img.shields.io/npm/v/@atlex/auth.svg?style=flat-square&color=7c3aed)](https://www.npmjs.com/package/@atlex/auth)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow?style=flat-square&logo=buy-me-a-coffee)](https://buymeacoffee.com/khamazaspyan)

## Installation

```bash
npm install @atlex/auth
```

## Quick start

Create an authenticatable user model:

```typescript
import { Authenticatable } from '@atlex/auth'

export interface User extends Authenticatable {
  id: string
  email: string
  password: string
  emailVerifiedAt: Date | null
}
```

Set up authentication in your service provider:

```typescript
import { AuthServiceProvider } from '@atlex/auth'
import { Application } from '@atlex/core'

const app = new Application()

app.register(AuthServiceProvider, {
  guards: {
    web: {
      driver: 'session',
      provider: 'users',
    },
    api: {
      driver: 'token',
      provider: 'users',
    },
  },
  providers: {
    users: async (app) => new DatabaseUserProvider(User),
  },
  hashing: {
    driver: 'bcrypt',
  },
})
```

Protect routes and authenticate users:

```typescript
import { AuthMiddleware, StartSession } from '@atlex/auth'

// Use middleware
router.use(StartSession)
router.post('/login', AuthMiddleware, async (req, res) => {
  const { email, password } = req.body

  if (await auth().attempt(email, password)) {
    const user = auth().user()
    res.json({ authenticated: true, user })
  } else {
    res.status(401).json({ message: 'Invalid credentials' })
  }
})
```

## Features

### Multi-Guard Authentication

- **SessionGuard**: Cookie-based session authentication
- **TokenGuard**: JWT/API token authentication
- Guard-aware `auth()` facade with per-request caching
- Stateless and stateful guard contracts

### Password Hashing

- **Bcrypt**: Industry-standard with adaptive work factors
- **Argon2**: OWASP-recommended, memory-hard algorithm
- **Scrypt**: Key derivation with configurable parameters
- Hash verification with automatic algorithm detection

### JWT & Tokens

- Token pair support (access + refresh tokens)
- Configurable expiration windows
- Token blacklisting with multiple store backends
- Refresh token repository for persistence
- Secure token parsing and validation

### Session Management

- Multiple session store backends
- **FileStore**: File-based session persistence
- **DatabaseStore**: SQL database session storage
- **RedisStore**: High-performance Redis backend
- **CookieStore**: Client-side encrypted sessions
- **NullStore**: In-memory (development/testing)
- Configurable session lifetime and garbage collection

### Authorization

- **Gate**: Allow/deny rules for any resource or action
- **Policies**: Class-based authorization logic
- Ability checks with user context
- BeforeCallback hooks for early authorization
- AfterCallback hooks for conditional enforcement

### Password Reset

- **PasswordBroker**: Secure reset token generation
- **PasswordBrokerManager**: Multi-broker support
- Configurable token expiration
- Email integration ready
- Verification before reset completion

### Email Verification

- **EmailVerifier**: Track and enforce email verification
- MustVerifyEmail contract for user models
- Middleware enforcement with redirect handling
- Signed verification links
- Resend verification logic

### Middleware

- **StartSession**: Initialize session per request
- **AuthMiddleware**: Guard-based authentication check
- **AuthorizeMiddleware**: Gate/policy enforcement
- **EnsureEmailIsVerified**: Verification gate
- **ThrottleLogins**: Brute-force protection with configurable lockout

### Events

- **Attempting**: Before credentials checked
- **Authenticated**: User successfully authenticated
- **Login**: User logged in (session/token issued)
- **Failed**: Authentication failed
- **Logout**: User logged out
- **Lockout**: Account locked after failed attempts
- **PasswordReset**: Password reset complete
- **PasswordResetLinkSent**: Reset email dispatched
- **Verified**: Email verified
- **Registered**: New user registered
- **CurrentDeviceLogout**: Logout from current device
- **OtherDeviceLogout**: Logout from other devices

## Core APIs

### AuthManager

Central facade for authentication operations:

```typescript
import { auth } from '@atlex/core'

// Get the active guard (from config)
const guard = auth().guard()

// Get a specific named guard
const webGuard = auth().guard('web')
const apiGuard = auth().guard('api')

// Attempt login with credentials
const success = await auth().attempt(email, password)

// Issue login (emit events, create session/token)
await auth().login(user)

// Get current authenticated user
const user = auth().user()

// Check if authenticated
const isAuth = auth().check()

// Check if guest (not authenticated)
const isGuest = auth().guest()

// Logout current user
await auth().logout()

// Validate password against user's hash
const valid = await auth().validate(user, plainPassword)

// Access password broker for reset flows
const broker = auth().broker('passwords')
```

### Guards

#### SessionGuard

Cookie-based session authentication:

```typescript
const guard = auth().guard('web')

// Authenticate user and create session
await guard.authenticate(user)

// Get current user
const user = guard.user()

// Check authentication
const authenticated = guard.check()

// Check guest
const guest = guard.guest()

// Logout (destroy session)
await guard.logout()
```

#### TokenGuard

JWT/API token authentication:

```typescript
const guard = auth().guard('api')

// Issue token pair (access + refresh)
const tokens = await guard.authenticate(user)
// { accessToken: '...', refreshToken: '...' }

// Get current user from token
const user = guard.user()

// Check if token is valid
const valid = guard.check()

// Logout (blacklist token)
await guard.logout()
```

### Password Hashing

```typescript
import { HashManager, BcryptHasher, Argon2Hasher } from '@atlex/auth'

const hash = new HashManager({
  driver: 'bcrypt',
  bcrypt: { rounds: 12 },
  argon2: { memory: 65536 },
})

// Hash a password
const digest = await hash.hash('plain-password')

// Verify password against hash
const valid = await hash.verify('plain-password', digest)

// Check if hash needs rehashing (algorithm update, etc.)
const needsRehash = hash.needsRehash(digest)
```

### JWT Provider

```typescript
import { JwtProvider, RefreshTokenRepository } from '@atlex/auth'

const jwt = new JwtProvider(config, refreshRepo)

// Create JWT token with custom claims
const token = jwt.encode({ sub: user.id, email: user.email })

// Parse and verify token
const claims = jwt.decode(token)

// Attempt login and get token pair
const result = await jwt.attempt(email, password)
if (result.succeeded) {
  console.log(result.accessToken, result.refreshToken)
}

// Refresh access token
const newAccessToken = await jwt.refresh(refreshToken)

// Revoke token via blacklist
await jwtBlacklist.blacklist(token)
```

### Authorization

#### Gate

```typescript
import { Gate } from '@atlex/auth'

const gate = new Gate()

// Define ability
gate.define('edit-post', (user: User, post: Post) => {
  return user.id === post.authorId
})

// Check authorization
if (gate.allows('edit-post', post)) {
  // Allow edit
}

// Or use can/cannot on request context
const allowed = req.auth.can('edit-post', post)
const denied = req.auth.cannot('edit-post', post)

// Use before callback for admin override
gate.before((user: User, ability: string) => {
  if (user.isAdmin) return true
})
```

#### Policy

```typescript
import { Policy } from '@atlex/auth'

class PostPolicy extends Policy {
  view(user: User, post: Post) {
    return !post.isDraft || user.id === post.authorId
  }

  edit(user: User, post: Post) {
    return user.id === post.authorId
  }

  delete(user: User, post: Post) {
    return user.id === post.authorId || user.isAdmin
  }
}

// Register policy
gate.policy(Post, PostPolicy)

// Check ability via policy
if (req.auth.can('edit', post)) {
  // Allow
}
```

### Password Reset

```typescript
import { PasswordBroker } from '@atlex/auth'

const broker = auth().broker('passwords')

// Send reset link to user
const sent = await broker.sendResetLink(email)

// Reset password with token
const status = await broker.reset(email, token, newPassword)

// Check if token exists and hasn't expired
const exists = await broker.tokenExists(email, token)
```

### Session Management

```typescript
import { Session, SessionManager } from '@atlex/auth'

const sessionManager = new SessionManager(config, store)

// Create new session
const session = sessionManager.create()

// Store data in session
session.put('user_id', user.id)
session.put('cart', { items: [...] })

// Retrieve data
const userId = session.get('user_id')
const all = session.all()

// Remove data
session.forget('cart')
session.flush()

// Regenerate ID (security)
await session.regenerate()
```

### Email Verification

```typescript
import { EmailVerifier } from '@atlex/auth'

const verifier = new EmailVerifier(config)

// Generate signed verification link
const link = verifier.verificationUrl(user)

// Mark user email as verified
await verifier.verify(user)

// Check if user has verified email
const isVerified = user.hasVerifiedEmail?.()
```

## Configuration

Create `config/auth.ts`:

```typescript
import type { AuthConfig } from '@atlex/auth'
import { DatabaseUserProvider } from '@atlex/auth'

export default {
  defaults: {
    guard: 'web',
    provider: 'users',
  },

  guards: {
    web: {
      driver: 'session',
      provider: 'users',
    },
    api: {
      driver: 'token',
      provider: 'users',
    },
  },

  providers: {
    users: async (app) => new DatabaseUserProvider(User),
  },

  jwt: {
    secret: process.env.JWT_SECRET!,
    algo: 'HS256',
    accessTokenExpires: '15m',
    refreshTokenExpires: '7d',
    issuer: 'atlex-app',
  },

  session: {
    driver: 'cookie',
    lifetime: 120, // minutes
    cookieName: 'ATLEXSESSID',
  },

  hashing: {
    driver: 'bcrypt',
    bcrypt: {
      rounds: 12,
    },
    argon2: {
      memory: 65536,
      time: 4,
      parallelism: 1,
    },
    scrypt: {
      cost: 16384,
      blockSize: 8,
      parallelization: 1,
      maxMemory: 64 * 1024 * 1024,
    },
  },

  passwords: {
    table: 'password_resets',
    expires: 3600, // seconds
  },

  throttle: {
    maxAttempts: 5,
    decay: 60, // minutes
  },
} as AuthConfig
```

## Examples

### Complete Login Flow

```typescript
import { Router, Request } from 'express'
import { auth, StartSession, AuthMiddleware } from '@atlex/auth'

const router = Router()

router.use(StartSession)

// Login page
router.get('/login', (req, res) => {
  res.render('login')
})

// Login handler
router.post('/login', AuthMiddleware, ThrottleLogins, async (req, res) => {
  const { email, password } = req.body

  const dispatcher = req.app.make('event.dispatcher')

  try {
    dispatcher.dispatch(new Attempting(email))

    const authenticated = await auth().attempt(email, password)

    if (!authenticated) {
      dispatcher.dispatch(new Failed(email))
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const user = auth().user()

    dispatcher.dispatch(new Authenticated(user))
    dispatcher.dispatch(new Login(user))

    res.json({ authenticated: true, user })
  } catch (error) {
    if (error instanceof LockoutError) {
      return res.status(429).json({ message: 'Too many attempts' })
    }
    throw error
  }
})

// Logout handler
router.post('/logout', async (req, res) => {
  const user = auth().user()

  await auth().logout()

  req.app.make('event.dispatcher').dispatch(new Logout(user))

  res.json({ message: 'Logged out successfully' })
})

export default router
```

### API Token Authentication

```typescript
import { TokenGuard } from '@atlex/auth'

router.post('/api/login', async (req, res) => {
  const { email, password } = req.body

  const guard = auth().guard('api') as TokenGuard

  const result = await guard.attempt(email, password)

  if (!result.succeeded) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  res.json({
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    expiresIn: 900, // 15 minutes
  })
})

// Refresh token
router.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body

  try {
    const newToken = await auth().guard('api').refresh(refreshToken)
    res.json({ accessToken: newToken })
  } catch (error) {
    res.status(401).json({ message: 'Token expired' })
  }
})
```

### Protected Routes with Authorization

```typescript
import { AuthorizeMiddleware } from '@atlex/auth'

// Require authentication
router.get(
  '/dashboard',
  (req, res, next) => {
    if (!auth().check()) {
      return res.redirect('/login')
    }
    next()
  },
  (req, res) => {
    const user = auth().user()
    res.render('dashboard', { user })
  },
)

// Require specific ability
router.patch('/posts/:id', AuthorizeMiddleware('edit-post'), async (req, res) => {
  const post = await Post.find(req.params.id)

  if (!req.auth.can('edit-post', post)) {
    return res.status(403).json({ message: 'Unauthorized' })
  }

  // Update post...
  res.json(post)
})

// Policy-based authorization
router.delete('/posts/:id', async (req, res) => {
  const post = await Post.find(req.params.id)
  const policy = gate.policy(Post)

  if (!policy.delete(auth().user(), post)) {
    return res.status(403).json({ message: 'Forbidden' })
  }

  await post.delete()
  res.json({ message: 'Deleted' })
})
```

### Password Reset Flow

```typescript
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body

  const broker = auth().broker('passwords')

  const sent = await broker.sendResetLink(email)

  res.json({
    message: 'Password reset link sent to email',
    sent,
  })
})

router.post('/reset-password', async (req, res) => {
  const { email, token, password, password_confirmation } = req.body

  if (password !== password_confirmation) {
    return res.status(422).json({ message: 'Passwords do not match' })
  }

  const broker = auth().broker('passwords')

  const status = await broker.reset(email, token, password)

  if (status === PasswordResetStatus.TOKEN_INVALID) {
    return res.status(422).json({ message: 'Invalid reset token' })
  }

  res.json({ message: 'Password reset successfully' })
})
```

### Email Verification

```typescript
router.get('/email/verify/:id/:hash', async (req, res) => {
  const user = await User.find(req.params.id)

  if (!user || !verifier.verify(user, req.params.hash)) {
    return res.status(422).json({ message: 'Invalid verification link' })
  }

  await user.markEmailAsVerified()

  res.json({ message: 'Email verified successfully' })
})

// Middleware to require verified email
router.post('/sensitive-action', EnsureEmailIsVerified, async (req, res) => {
  // Only verified users can reach here
  const user = auth().user()
  // ...
})
```

## API Overview

### Authentication

- `AuthManager.guard(name?)` - Resolve a guard
- `AuthManager.attempt(email, password)` - Attempt login
- `AuthManager.login(user)` - Log user in
- `AuthManager.user()` - Get current user
- `AuthManager.check()` - Check if authenticated
- `AuthManager.guest()` - Check if guest
- `AuthManager.logout()` - Log user out
- `AuthManager.validate(user, password)` - Verify password
- `AuthManager.broker(name)` - Get password broker

### Guards

- `SessionGuard.authenticate(user)` - Create session
- `SessionGuard.user()` - Get user from session
- `SessionGuard.check()` - Check session validity
- `SessionGuard.logout()` - Destroy session
- `TokenGuard.attempt(email, password)` - Login and issue tokens
- `TokenGuard.refresh(token)` - Refresh access token
- `TokenGuard.user()` - Get user from token
- `TokenGuard.logout()` - Blacklist token

### Password Hashing

- `HashManager.hash(password)` - Hash password
- `HashManager.verify(password, hash)` - Verify password
- `HashManager.needsRehash(hash)` - Check if rehash needed
- `BcryptHasher`, `Argon2Hasher`, `ScryptHasher` - Algorithm implementations

### JWT

- `JwtProvider.encode(claims)` - Create JWT
- `JwtProvider.decode(token)` - Verify and decode
- `JwtProvider.attempt(email, password)` - Login and get tokens
- `JwtBlacklist.blacklist(token)` - Revoke token
- `RefreshTokenRepository.store(token, user, expiry)` - Store refresh token

### Authorization

- `Gate.define(ability, callback)` - Define ability
- `Gate.policy(model, Policy)` - Register policy
- `Gate.allows(ability, ...args)` - Check permission
- `Gate.denies(ability, ...args)` - Check denial
- `GateForUser.can(ability, ...args)` - Check as user
- `Policy` - Base class for policy definitions

### Session

- `Session.put(key, value)` - Store value
- `Session.get(key)` - Retrieve value
- `Session.all()` - Get all data
- `Session.forget(key)` - Remove value
- `Session.flush()` - Clear session
- `Session.regenerate()` - Generate new ID

### Password Reset

- `PasswordBroker.sendResetLink(email)` - Send reset link
- `PasswordBroker.reset(email, token, password)` - Reset password
- `PasswordBroker.tokenExists(email, token)` - Check token

## Events

All events are dispatched via `EventDispatcher`:

```typescript
import { Attempting, Authenticated, Login, Failed, Logout } from '@atlex/auth'

dispatcher.on(Authenticated, (event) => {
  console.log('User authenticated:', event.user)
})

dispatcher.on(Login, (event) => {
  console.log('User logged in:', event.user)
})

dispatcher.on(Failed, (event) => {
  console.log('Authentication failed:', event.email)
})
```

## Documentation

For more information, visit [atlex.dev/guide/auth](https://atlex.dev/guide/auth)

## License

## MIT

Part of [Atlex](https://atlex.dev) — A modern framework for Node.js.
