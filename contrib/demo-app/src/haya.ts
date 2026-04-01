/**
 * Minimal Haya Auth client
 *
 * Demonstrates how to call haya-rs from a browser frontend.
 *
 * Configuration:
 *   VITE_HAYA_URL – base URL for the auth API (default: /auth, proxied by Vite
 *                   in development to http://localhost:9999)
 */

const BASE_URL = (import.meta.env.VITE_HAYA_URL as string | undefined) ?? '/auth'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface User {
  id: string
  aud: string
  role: string
  email?: string
  phone?: string
  email_confirmed_at?: string
  phone_confirmed_at?: string
  confirmed_at?: string
  last_sign_in_at?: string
  app_metadata: Record<string, unknown>
  user_metadata: Record<string, unknown>
  created_at?: string
  updated_at?: string
  is_anonymous: boolean
}

export interface Session {
  access_token: string
  token_type: string
  expires_in: number
  expires_at: number
  refresh_token: string
  user: User
}

export class HayaError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'HayaError'
    this.status = status
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init.headers },
    ...init,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, unknown>
    const message = (body['msg'] ?? body['message'] ?? res.statusText) as string
    throw new HayaError(message, res.status)
  }
  // 204 No Content (e.g. logout)
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

function bearer(accessToken: string): HeadersInit {
  return { Authorization: `Bearer ${accessToken}` }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const haya = {
  /**
   * Sign up a new user with email & password.
   * Returns the new User. If `MAILER_AUTOCONFIRM=true` on the server the user
   * is immediately confirmed; otherwise they must verify their email first.
   */
  signUp(
    email: string,
    password: string,
    metadata?: Record<string, unknown>,
  ): Promise<User> {
    return request<User>('/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password, data: metadata }),
    })
  },

  /**
   * Sign in with email & password.
   * Returns a Session containing the access token, refresh token and User.
   */
  signIn(email: string, password: string): Promise<Session> {
    return request<Session>('/token?grant_type=password', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
  },

  /**
   * Exchange a refresh token for a new Session.
   * Call this before the access token expires to maintain the session.
   */
  refreshSession(refreshToken: string): Promise<Session> {
    return request<Session>('/token?grant_type=refresh_token', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
  },

  /**
   * Fetch the currently authenticated user's profile.
   * Requires a valid access token.
   */
  getUser(accessToken: string): Promise<User> {
    return request<User>('/user', {
      headers: bearer(accessToken),
    })
  },

  /**
   * Update the currently authenticated user.
   * Requires a valid access token.
   */
  updateUser(
    accessToken: string,
    updates: {
      email?: string
      password?: string
      data?: Record<string, unknown>
    },
  ): Promise<User> {
    return request<User>('/user', {
      method: 'PUT',
      headers: bearer(accessToken),
      body: JSON.stringify(updates),
    })
  },

  /**
   * Sign out the current session (or all sessions).
   *   scope = 'local'   – current session only (default)
   *   scope = 'global'  – all sessions for this user
   *   scope = 'others'  – all sessions except the current one
   */
  signOut(
    accessToken: string,
    scope?: 'local' | 'global' | 'others',
  ): Promise<void> {
    const qs = scope && scope !== 'local' ? `?scope=${scope}` : ''
    return request<void>(`/logout${qs}`, {
      method: 'POST',
      headers: bearer(accessToken),
    })
  },
}
