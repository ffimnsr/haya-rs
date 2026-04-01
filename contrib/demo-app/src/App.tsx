import { useEffect, useState } from 'react'
import { haya, HayaError, type Session, type User } from './haya'
import './App.css'

const SESSION_KEY = 'haya_session'

function loadStoredSession(): Session | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

function saveSession(s: Session) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(s))
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY)
}

// ─── Auth forms ───────────────────────────────────────────────────────────────

type View = 'signin' | 'signup'

function AuthForms({
  onSession,
  onSignedUp,
}: {
  onSession: (s: Session) => void
  onSignedUp: (u: User, password: string) => void
}) {
  const [view, setView] = useState<View>('signin')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  function switchView(v: View) {
    setView(v)
    setError(null)
  }

  async function handleSignIn(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    setError(null)
    setLoading(true)
    try {
      const s = await haya.signIn(
        fd.get('email') as string,
        fd.get('password') as string,
      )
      onSession(s)
    } catch (err) {
      setError(err instanceof HayaError ? err.message : 'Sign in failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleSignUp(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const email = fd.get('email') as string
    const password = fd.get('password') as string
    setError(null)
    setLoading(true)
    try {
      const user = await haya.signUp(email, password)
      onSignedUp(user, password)
    } catch (err) {
      setError(err instanceof HayaError ? err.message : 'Sign up failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <div className="tab-bar">
        <button
          className={view === 'signin' ? 'active' : ''}
          onClick={() => switchView('signin')}
        >
          Sign In
        </button>
        <button
          className={view === 'signup' ? 'active' : ''}
          onClick={() => switchView('signup')}
        >
          Sign Up
        </button>
      </div>

      {error && <p className="error-msg">{error}</p>}

      {view === 'signin' ? (
        <form onSubmit={handleSignIn}>
          <label>
            Email
            <input name="email" type="email" autoComplete="email" required />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleSignUp}>
          <label>
            Email
            <input name="email" type="email" autoComplete="email" required />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="new-password"
              minLength={6}
              required
            />
          </label>
          <button type="submit" disabled={loading}>
            {loading ? 'Creating account…' : 'Sign Up'}
          </button>
        </form>
      )}
    </div>
  )
}

// ─── Confirm-email notice ─────────────────────────────────────────────────────

function PendingConfirmation({
  user,
  onGoToSignIn,
}: {
  user: User
  onGoToSignIn: () => void
}) {
  return (
    <div className="card">
      <p className="confirm-msg">
        Account created for <strong>{user.email}</strong>.
        <br />
        Check your inbox to confirm your email, then sign in.
      </p>
      <button onClick={onGoToSignIn}>Go to Sign In</button>
    </div>
  )
}

// ─── Signed-in profile ────────────────────────────────────────────────────────

function Profile({
  session,
  onSession,
  onSignOut,
}: {
  session: Session
  onSession: (s: Session) => void
  onSignOut: () => void
}) {
  const { user } = session
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleRefresh() {
    setError(null)
    setLoading(true)
    try {
      const s = await haya.refreshSession(session.refresh_token)
      onSession(s)
    } catch (err) {
      setError(err instanceof HayaError ? err.message : 'Refresh failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleSignOut() {
    setLoading(true)
    try {
      await haya.signOut(session.access_token)
    } finally {
      onSignOut()
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Session</h2>
      {error && <p className="error-msg">{error}</p>}
      <dl className="field-list">
        <dt>User ID</dt>
        <dd>
          <code>{user.id}</code>
        </dd>
        <dt>Email</dt>
        <dd>{user.email ?? '–'}</dd>
        <dt>Role</dt>
        <dd>{user.role}</dd>
        <dt>Confirmed</dt>
        <dd>
          {user.email_confirmed_at
            ? new Date(user.email_confirmed_at).toLocaleString()
            : 'Pending'}
        </dd>
        <dt>Access token</dt>
        <dd>
          <code className="token-preview">
            {session.access_token.slice(0, 48)}…
          </code>
        </dd>
        <dt>Expires in</dt>
        <dd>{session.expires_in}s</dd>
      </dl>
      <div className="button-row">
        <button onClick={handleRefresh} disabled={loading}>
          Refresh Token
        </button>
        <button className="danger" onClick={handleSignOut} disabled={loading}>
          Sign Out
        </button>
      </div>
    </div>
  )
}

// ─── Root ─────────────────────────────────────────────────────────────────────

type AppState =
  | { kind: 'unauthenticated' }
  | { kind: 'pending_confirmation'; user: User }
  | { kind: 'authenticated'; session: Session }

function App() {
  const [appState, setAppState] = useState<AppState>({ kind: 'unauthenticated' })

  // Rehydrate session from localStorage on first mount
  useEffect(() => {
    const stored = loadStoredSession()
    if (!stored) return

    const nowSec = Math.floor(Date.now() / 1000)
    if (stored.expires_at > nowSec) {
      // Token still valid
      setAppState({ kind: 'authenticated', session: stored })
    } else {
      // Token expired — try a silent refresh
      haya
        .refreshSession(stored.refresh_token)
        .then((s) => {
          saveSession(s)
          setAppState({ kind: 'authenticated', session: s })
        })
        .catch(() => {
          clearSession()
        })
    }
  }, [])

  function handleSession(s: Session) {
    saveSession(s)
    setAppState({ kind: 'authenticated', session: s })
  }

  async function handleSignedUp(user: User, password: string) {
    // If the server auto-confirmed the user (MAILER_AUTOCONFIRM=true), sign in
    // immediately. Otherwise show the email-confirmation notice.
    if (user.email_confirmed_at && user.email) {
      try {
        const s = await haya.signIn(user.email, password)
        setAppState({ kind: 'authenticated', session: s })
        return
      } catch {
        // Fall through to the confirmation screen
      }
    }
    setAppState({ kind: 'pending_confirmation', user })
  }

  function handleSignOut() {
    clearSession()
    setAppState({ kind: 'unauthenticated' })
  }

  return (
    <div className="demo-container">
      <header className="demo-header">
        <h1>Haya Auth Demo</h1>
        <p className="demo-subtitle">
          {appState.kind === 'authenticated'
            ? `Signed in as ${appState.session.user.email ?? appState.session.user.id}`
            : 'Integration example for haya-rs'}
        </p>
      </header>

      {appState.kind === 'unauthenticated' && (
        <AuthForms onSession={handleSession} onSignedUp={handleSignedUp} />
      )}

      {appState.kind === 'pending_confirmation' && (
        <PendingConfirmation
          user={appState.user}
          onGoToSignIn={() => setAppState({ kind: 'unauthenticated' })}
        />
      )}

      {appState.kind === 'authenticated' && (
        <Profile
          session={appState.session}
          onSession={handleSession}
          onSignOut={handleSignOut}
        />
      )}

      {appState.kind !== 'authenticated' && (
        <p className="demo-hint">
          API calls are proxied to <code>http://localhost:9999</code>. Start
          haya-rs before using the demo.
        </p>
      )}
    </div>
  )
}

export default App
