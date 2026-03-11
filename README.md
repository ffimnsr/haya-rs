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

Haya does not run migrations automatically on startup. Apply the SQL in [migrations/1732763425725_create_role_auth.sql](migrations/1732763425725_create_role_auth.sql) against your PostgreSQL instance before starting the server.

### 3. Configure environment variables

At minimum, set these variables:

```bash
export DATABASE_URL="postgres://e_auth:mysecretpassword@localhost:5432/haya"
export JWT_SECRET="replace-this-with-a-secret-at-least-32-characters-long"
```

Useful optional variables:

```bash
export PORT=9999
export SITE_URL="http://localhost:9999"
export JWT_EXPIRY=3600
export REFRESH_TOKEN_EXPIRY=1209600
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
export MAILER_AUTOCONFIRM=false
```

Notes:

- `JWT_SECRET` is required in normal operation and must be at least 32 characters.
- For local development only, you can set `HAYA_DEV_MODE=1` to allow an insecure built-in JWT secret.
- If `GOTRUE_JWT_ISSUER` or `JWT_ISSUER` is not set, Haya uses `SITE_URL` as the issuer.

### 4. Run the server

```bash
cargo run
```

The server listens on `PORT`, which defaults to `9999`.

### 5. Verify the instance

```bash
curl http://localhost:9999/health
```

## Implemented HTTP Endpoints

Public auth routes:

- `GET /health`
- `GET /settings`
- `POST /signup`
- `POST /token`
- `POST /verify`
- `POST /recover`
- `POST /resend`
- `POST /magiclink`
- `POST /otp`
- `POST /logout`
- `GET /user`
- `PUT /user`

Admin routes:

- `GET /admin/users`
- `POST /admin/users`
- `GET /admin/users/:id`
- `PUT /admin/users/:id`
- `DELETE /admin/users/:id`

## Configuration Reference

### Required

- `DATABASE_URL`: PostgreSQL connection string.
- `JWT_SECRET`: signing secret for JWTs. Must be at least 32 characters.

### Optional

- `DEFAULT_DATABASE_URL`: fallback if `DATABASE_URL` is unset.
- `PORT`: HTTP port. Defaults to `9999`.
- `SITE_URL`: base URL used by the service. Defaults to `http://localhost:9999`.
- `GOTRUE_JWT_ISSUER`: preferred JWT issuer override.
- `JWT_ISSUER`: fallback issuer override.
- `JWT_EXPIRY`: access token lifetime in seconds. Defaults to `3600`.
- `REFRESH_TOKEN_EXPIRY`: refresh token lifetime in seconds. Defaults to `1209600`.
- `INSTANCE_ID`: explicit UUID for the auth instance.
- `MAILER_AUTOCONFIRM`: enables automatic confirmation when set to `true` or `1`.
- `CORS_ALLOWED_ORIGINS`: comma-separated list of allowed origins. If omitted, CORS is permissive.
- `HAYA_DEV_MODE`: enables an insecure built-in JWT secret for local development only.

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
