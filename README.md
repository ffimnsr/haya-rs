# Haya

Haya is a Supabase Auth (GoTrue)-compatible authentication server implemented in Rust.

The repository currently exposes a focused set of auth and admin endpoints over Axum with PostgreSQL as the backing store.

## What Haya Does

- Provides a Rust implementation of common GoTrue-style authentication flows.
- Issues JWT access tokens and refresh tokens.
- Stores users, sessions, refresh tokens, identities, and MFA data in PostgreSQL.
- Exposes a small HTTP API for user auth flows and admin user management.

## Quick Start

### 1. Prerequisites

- Rust toolchain
- PostgreSQL
- OpenSSL, if you want to generate EC keys locally

### 2. Create the database schema

Haya does not run migrations automatically on startup. Apply the base schema in [migrations/202411280001_create_role_auth.sql](migrations/202411280001_create_role_auth.sql) and every newer migration in `migrations/` against your PostgreSQL instance before starting the server.

### 3. Configure environment variables

At minimum, set these variables:

```bash
export DATABASE_URL="postgres://e_auth:change-me@localhost:5432/haya"
export JWT_SECRET="replace-this-with-a-secret-at-least-32-characters-long"
export MFA_ENCRYPTION_KEY="replace-this-with-a-separate-secret"
```

Useful optional variables:

```bash
export PORT=9999
export SITE_URL="http://localhost:9999"
export SITE_NAME="Haya"
export JWT_EXPIRY=3600
export REFRESH_TOKEN_EXPIRY=1209600
export SESSION_IDLE_TIMEOUT_SECS=86400
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
export ALLOWED_REDIRECT_ORIGINS="http://localhost:3000"
export MAILER_AUTOCONFIRM=false
```

Notes:

- `JWT_SECRET` is required in normal operation and must be at least 32 characters.
- `MFA_ENCRYPTION_KEY` is required and must be separate from `JWT_SECRET` so TOTP secrets use independent key material.
- For local development only, you can set `HAYA_DEV_MODE=1` to allow an ephemeral development JWT secret when `JWT_SECRET` is unset.
- If `GOTRUE_JWT_ISSUER` or `JWT_ISSUER` is not set, Haya uses `SITE_URL` as the issuer.
- A complete starting template is available in [.env.example](.env.example).

### 4. Run the server

```bash
cargo run
```

The server listens on `PORT`, which defaults to `9999`.

You can also run the binary in CLI mode against the configured PostgreSQL database:

```bash
cargo run -- status
cargo run -- heartbeat
cargo run -- settings
cargo run -- sso list
cargo run -- user list
cargo run -- admin list
```

Without a subcommand, `haya` still starts the HTTP server.

### 5. Verify the instance

```bash
curl http://localhost:9999/health
```

## Implemented HTTP Endpoints

Public auth routes:

- `GET /health`
- `GET /settings`
- `GET /authorize`
- `GET /callback`
- `POST /signup`
- `POST /token`
- `POST /verify`
- `POST /recover`
- `POST /resend`
- `POST /magiclink`
- `POST /otp`
- `GET /factors`
- `POST /factors`
- `POST /factors/:id/verify`
- `DELETE /factors/:id`
- `POST /mfa/factors`
- `POST /logout`
- `GET /user`
- `PUT /user`

Admin routes:

- `GET /admin/users`
- `POST /admin/users`
- `GET /admin/users/:id`
- `PUT /admin/users/:id`
- `DELETE /admin/users/:id`

## CLI Commands

The CLI talks directly to the configured database defined by `DATABASE_URL`, so it works whether or not an HTTP server is already running.

Examples:

```bash
haya status
haya heartbeat
haya settings
haya config validate
haya db status
haya db migrate
haya db vacuum-token-tables
haya sso list
haya sso show acme
haya sso add --name acme --issuer https://id.example.com/realms/acme --client-id haya --client-secret secret --redirect-uri http://localhost:9999/callback --allowed-domain example.com
haya sso test acme
haya sso discover acme
haya sso sync-cache
haya reload
haya doctor
haya audit list
haya audit user user@example.com
haya audit tail --follow
haya mfa list user@example.com
haya mfa delete user@example.com --factor-id 00000000-0000-0000-0000-000000000000
haya mfa reset user@example.com
haya user show user@example.com
haya user sessions user@example.com
haya user reset-password user@example.com --send-link
haya session list --user user@example.com
haya session show 00000000-0000-0000-0000-000000000000
haya session revoke-others --session-id 00000000-0000-0000-0000-000000000000
haya session revoke --session-id 00000000-0000-0000-0000-000000000000
haya token inspect eyJ...
haya token issue user@example.com --method admin_cli --aal aal1
haya token cleanup --dry-run

haya admin list
haya admin add --email admin@example.com --password 'change-me' --role service_role --verified
haya admin update admin@example.com --role supabase_admin --ban-duration 24h
haya admin verify admin@example.com
haya admin delete admin@example.com

haya user list --email-like example.com
haya user add --email user@example.com --password 'change-me'
haya user update user@example.com --phone '+15555550123' --unban
haya user verify user@example.com
haya user delete user@example.com
```

Supported command groups:

- `haya serve`
- `haya status`
- `haya heartbeat`
- `haya settings`
- `haya config validate`
- `haya db status|migrate|vacuum-token-tables`
- `haya reload`
- `haya doctor`
- `haya audit list|user|tail`
- `haya mfa list|delete|reset`
- `haya session list|show|revoke|revoke-others`
- `haya session show`
- `haya token cleanup|issue|inspect`
- `haya sso list|show|add|update|delete|test|discover|sync-cache`
- `haya admin list|add|update|verify|delete`
- `haya user list|show|sessions|reset-password|add|update|verify|delete`

## Configuration Reference

### Required

- `DATABASE_URL`: PostgreSQL connection string.
- `JWT_SECRET`: signing secret for JWTs. Must be at least 32 characters.

### Optional

- `DEFAULT_DATABASE_URL`: fallback if `DATABASE_URL` is unset.
- `DATABASE_MAX_CONNECTIONS`: PostgreSQL pool size. Defaults to `20`.
- `DATABASE_ACQUIRE_TIMEOUT_SECS`: PostgreSQL pool acquire timeout in seconds. Defaults to `5`.
- `PORT`: HTTP port. Defaults to `9999`.
- `SITE_URL`: base URL used by the service. Defaults to `http://localhost:9999`.
- `SITE_NAME`: display name used in email templates and UI-facing messages. Defaults to `Haya`.
- `GOTRUE_JWT_ISSUER`: preferred JWT issuer override.
- `JWT_ISSUER`: fallback issuer override.
- `JWT_EXPIRY`: access token lifetime in seconds. Defaults to `3600`.
- `MFA_ENCRYPTION_KEY`: dedicated key material for encrypting stored TOTP secrets. This is required and must not reuse `JWT_SECRET`.
- `REFRESH_TOKEN_EXPIRY`: refresh token lifetime in seconds. Defaults to `1209600`.
- `SESSION_IDLE_TIMEOUT_SECS`: idle session timeout in seconds. Defaults to `86400`.
- `INSTANCE_ID`: explicit UUID for the auth instance.
- `MAILER_AUTOCONFIRM`: enables automatic confirmation when set to `true` or `1`.
- `CORS_ALLOWED_ORIGINS`: comma-separated list of allowed browser origins for CORS. If omitted, CORS is permissive in dev mode and defaults to `SITE_URL` otherwise.
- `ALLOWED_REDIRECT_ORIGINS`: comma-separated list of allowed OIDC `redirect_to` origins, in addition to `SITE_URL`.
- `ALLOWED_REDIRECT_PATH_PREFIXES`: optional comma-separated list of allowed path prefixes for OIDC `redirect_to` URLs. When set, redirects must match both an allowed origin and one of these prefixes.
- `OIDC_RESPONSE_MODE`: set to `form_post` to request OIDC providers post the callback to `/callback` instead of using the default query redirect.
- `SMTP_HOST`: SMTP server hostname. If unset, email sending is disabled.
- `SMTP_PORT`: SMTP server port. Defaults to `587`.
- `SMTP_USERNAME`: SMTP username for authenticated SMTP sessions.
- `SMTP_PASSWORD`: SMTP password for authenticated SMTP sessions.
- `SMTP_TLS`: when set to `false` or `0`, disables STARTTLS. Defaults to `true`.
- `SMTP_FROM_EMAIL`: sender email address. Defaults to `noreply@example.com`.
- `SMTP_FROM_NAME`: sender display name. Defaults to `SITE_NAME`.
- `EMAIL_TEMPLATES_DIR`: directory containing override email templates. Defaults to `./templates/email`.
- `HAYA_DEV_MODE`: when `JWT_SECRET` is unset, enables an ephemeral development JWT secret for local development only.
- `HAYA_PID_FILE`: overrides the pid file path used by `haya reload` and `haya doctor`. Defaults to `/tmp/haya.pid`.

### systemd watchdog

The sample unit at [contrib/systemd/haya.service](contrib/systemd/haya.service) uses `Type=notify` with `WatchdogSec=30s`.
Haya sends `READY=1` after the HTTP listener is bound, periodic watchdog pings while an in-process loopback probe to `/health` succeeds, and `STOPPING=1` during shutdown.

This is stronger than checking whether the PID still exists because watchdog pings stop when the process is no longer making progress through its own health path.

Useful commands:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now haya
systemctl status haya
journalctl -u haya -f
```

When the watchdog fires, systemd treats it as a service failure and restarts the unit according to `Restart=on-failure`.
You will typically see log lines in `systemctl status haya` or `journalctl -u haya` indicating that the watchdog timeout expired and that systemd scheduled a restart for the service.

### OIDC SSO

Haya can initiate a generic OIDC login flow for enterprise identity providers such as Keycloak, Okta, Entra ID, and Auth0. Providers are now stored in PostgreSQL and managed with the CLI.

Add a provider:

```bash
haya sso add \
  --name acme \
  --issuer https://id.example.com/realms/acme \
  --client-id haya \
  --client-secret replace-me \
  --redirect-uri http://localhost:9999/callback \
  --allowed-domain example.com
```

If the server is already running, reload the in-memory provider cache:

```bash
haya reload
```

Start the browser flow with:

```bash
curl -i "http://localhost:9999/authorize?provider=acme&redirect_to=http://localhost:3000/auth/callback"
```

`redirect_to` must stay on `SITE_URL` or one of the configured `CORS_ALLOWED_ORIGINS`. If you set `ALLOWED_REDIRECT_PATH_PREFIXES`, it must also stay under one of those path prefixes.

If your identity provider supports it, set `OIDC_RESPONSE_MODE=form_post` to request a POST callback to `/callback`. This is the stricter browser-side option and pairs with Haya's POST `/callback` handler.

After a successful provider login, Haya creates or reuses the mapped identity, then redirects to `redirect_to?code=<one-time-code>`. Exchange that code through `POST /token?grant_type=oidc_callback` to receive the normal token payload.

If the user has a verified TOTP factor, the same one-time callback code exchange returns the pending MFA payload instead. Send MFA bearer tokens only in the `Authorization` header for both `POST /mfa/factors` and `POST /token?grant_type=mfa_totp`.

### TOTP MFA

Haya now supports TOTP-based MFA for both password and OIDC sign-in. TOTP secrets are AES-GCM encrypted at rest, sessions move from `aal1` to `aal2` after successful verification, and AMR claims are stored in PostgreSQL and preserved across refresh token rotation.

Enroll a factor from an authenticated session:

```bash
curl -X POST http://localhost:9999/factors \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"friendly_name":"Primary phone","issuer":"Haya"}'
```

The response includes a Base32 secret and an `otpauth://` URI you can load into an authenticator app.

Verify the new factor:

```bash
curl -X POST http://localhost:9999/factors/<factor-id>/verify \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

When a user with verified TOTP factors signs in through `POST /token?grant_type=password`, the response switches from a session payload to:

```json
{
  "mfa_required": true,
  "mfa_token": "pending-token",
  "factors": [
    {
      "id": "factor-id",
      "friendly_name": "Primary phone",
      "factor_type": "totp",
      "status": "verified",
      "created_at": "2026-04-04T00:00:00Z",
      "updated_at": "2026-04-04T00:00:00Z",
      "last_challenged_at": null
    }
  ]
}
```

Complete the second factor:

```bash
curl -X POST "http://localhost:9999/token?grant_type=mfa_totp" \
  -H "Authorization: Bearer $MFA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"factor_id":"factor-id","code":"123456"}'
```

Delete a verified factor with an `aal2` session:

```bash
curl -X DELETE http://localhost:9999/factors/<factor-id> \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Changing password, email, or phone through `PUT /user` now requires reauthentication. For password-based users, send `current_password`; if the account has MFA enabled, the session must also be `aal2`.

## Development

Common commands from [tasks.yaml](tasks.yaml):

- `cargo run`
- `cargo fmt --all`
- `cargo clippy --all-features --all-targets --tests --benches -- -Dclippy::all`
- `cargo check`
- `cargo build`

Integration tests currently require a running database.

## Running With systemd

A sample systemd unit is available at [contrib/systemd/haya.service](contrib/systemd/haya.service), with an example environment file at [contrib/systemd/haya.env.example](contrib/systemd/haya.env.example).

The unit assumes:

- the `haya` binary is installed at `/usr/local/bin/haya`
- runtime configuration lives at `/etc/haya/haya.env`
- the service runs as a dedicated `haya` user and group
- writable state lives under `/var/lib/haya`

Example installation steps on Linux:

```bash
cargo build --release
sudo useradd --system --home /var/lib/haya --create-home --shell /usr/sbin/nologin haya
sudo install -Dm755 ./target/release/haya /usr/local/bin/haya
sudo install -Dm644 ./contrib/systemd/haya.service /etc/systemd/system/haya.service
sudo install -Dm640 ./contrib/systemd/haya.env.example /etc/haya/haya.env
sudo chown root:haya /etc/haya/haya.env
sudo systemctl daemon-reload
sudo systemctl enable --now haya
```

After editing `/etc/haya/haya.env`, restart the service:

```bash
sudo systemctl restart haya
sudo systemctl status haya
```

## Generating EC Keys

Generate a private key:

```bash
openssl ecparam -genkey -noout -name prime256v1 \
  | openssl pkcs8 -topk8 -nocrypt -out ./certs/priv-key.pem
```

Generate the matching public key:

```bash
openssl ec -in ./certs/priv-key.pem -pubout -out ./certs/pub.pem
```

## License

Licensed under either of:

- Apache License, Version 2.0, see [LICENSE-APACHE](LICENSE-APACHE)
- MIT license, see [LICENSE-MIT](LICENSE-MIT)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
