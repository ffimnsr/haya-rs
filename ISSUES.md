# Passkey Relying Party Implementation

## Project goal

Implement a native WebAuthn relying party as the unpublished workspace crate `crates/haya-passkey-rp`, without `webauthn-rs`. The RP crate uses the MIT/Apache-2.0 `1Password/passkey-rs` workspace for WebAuthn wire types, CBOR/COSE types, and cryptographic helpers. The root `haya` package integrates that protocol crate with PostgreSQL ceremony state, Axum handlers, replay prevention, auditing, rate limiting, and session issuance.

## Fixed implementation policy

- `haya-passkey-rp` is an unpublished internal workspace crate with `publish = false` and no dependency on the root `haya` package.
- The RP crate owns immutable RP configuration, challenge generation, option construction, client-data validation, authenticator-data parsing, attestation verification, assertion verification, counter policy, and RP credential types.
- The root `haya` package owns environment parsing, feature enablement, `AppState`, Axum, SQLx, migrations, flow persistence, user ownership, reauthentication, rate limiting, auditing, and session issuance.
- The RP crate must not depend on `axum`, `sqlx`, Haya models, Haya errors, JWT/session code, environment variables, audit code, or rate-limit code.
- Production code must not instantiate `passkey_client::Client` or `passkey_authenticator::Authenticator`.
- Production WebAuthn JSON uses `passkey-types` with `serialize_bytes_as_base64_string` enabled.
- The first release advertises and accepts only ES256 (`alg = -7`, EC2/P-256).
- The RP stores only public credential material. It must never store `passkey_types::Passkey`, authenticator private keys, or software-authenticator credential stores.
- Registration requests a discoverable credential with resident key `required`, user verification `required`, and attestation conveyance `none`.
- Authentication is username-less: `allowCredentials` is omitted and the returned user handle identifies the account.
- A successful assertion with verified user presence and user verification creates an `aal2` Haya session with AMR method `webauthn`.
- Challenges are 32 random bytes, expire after 300 seconds, are persisted by Haya in PostgreSQL, and are one-use.
- RP origins are exact normalized origins. HTTPS is mandatory except for `http://localhost` when Haya constructs the RP with development mode enabled; IP-address origins remain unsupported.
- Credential IDs and user handles are stored by Haya as `bytea`; base64url is used only at JSON boundaries.
- The RP accepts only the `none` attestation statement format in the first release and fails closed for every other format.
- Every unsupported, malformed, expired, replayed, or cryptographically invalid ceremony maps to a generic passkey authentication or registration error without exposing credential or account existence.

---

## Phase 1 — Workspace crate, dependencies, public boundary, and RP configuration

### Goal

Create the unpublished `haya-passkey-rp` workspace crate, give it the minimal `passkey-rs` dependencies, define its narrow protocol API, and inject one validated RP instance through Haya's `AppState` without enabling passkeys by default.

### Overview

This phase establishes the dependency direction before protocol implementation. The RP crate remains deterministic and application-independent; the root package remains responsible for runtime configuration and side effects. Existing authentication behavior must remain unchanged when `PASSKEY_ENABLED` is unset or false.

### Rules

- Do not add `webauthn-rs` or any crate that wraps it.
- Do not add the umbrella `passkey` crate to production dependencies.
- Do not let `haya-passkey-rp` depend on the root `haya` package.
- Do not place SQL, HTTP, environment, logging, audit, rate-limit, or session behavior in the RP crate.
- Do not infer the RP ID from `SITE_URL`.
- Do not allow passkeys to start with incomplete or invalid configuration.
- Keep the public API disabled until all required RP settings validate successfully.

### Work items

- [x] Convert the repository root manifest into a workspace containing the existing package and the RP crate.
  - [x] Add `[workspace]` to the root `Cargo.toml` with members `"."` and `"crates/haya-passkey-rp"`.
  - [x] Set workspace resolver to `"2"`.
  - [x] Preserve the existing root `[package]`, dependency, target, and binary behavior.
  - [x] Add `haya-passkey-rp = { path = "crates/haya-passkey-rp" }` to the root package dependencies.
  - [x] Add a workspace metadata test that runs `cargo metadata` and asserts both packages are workspace members.

- [x] Create `crates/haya-passkey-rp/Cargo.toml` as an unpublished library crate.
  - [x] Set package name to `haya-passkey-rp`, version to `0.1.0`, edition to `2024`, and `publish = false`.
  - [x] Set license to `MIT OR Apache-2.0`.
  - [x] Add `passkey-types` version `0.6` with `serialize_bytes_as_base64_string` enabled.
  - [x] Add `passkey-crypto` version `0.1` with default features disabled and `rust-crypto` enabled.
  - [x] Add `p256` version `0.14` with ECDSA verification support.
  - [x] Add only protocol-support dependencies required for serialization, URLs, constant-time comparison, and error types.
  - [x] Run dependency resolution and commit the resulting `Cargo.lock` changes.

- [x] Create the `crates/haya-passkey-rp/src/` module tree.
  - [x] Create `lib.rs` and re-export only `PasskeyRp`, `PasskeyConfig`, ceremony input/output types, `RpCredential`, and `RpError`.
  - [x] Create `config.rs` for RP configuration validation.
  - [x] Create `credential.rs` for the RP-owned stored public credential type.
  - [x] Create `client_data.rs` for collected-client-data validation.
  - [x] Create `authenticator_data.rs` for bounded authenticator-data parsing.
  - [x] Create `attestation.rs` for attestation-object parsing and registration verification.
  - [x] Create `assertion.rs` for authentication assertion verification.
  - [x] Create `error.rs` for protocol errors without Haya-specific response mapping.
  - [x] Keep parser helpers and internal structures private unless they are required in a ceremony input or result.

- [x] Define the side-effect-free public RP API in `crates/haya-passkey-rp/src/lib.rs`.
  - [x] Implement `PasskeyRp::new(PasskeyConfig) -> Result<Self, RpError>`.
  - [x] Implement `start_registration` to return WebAuthn creation options plus serializable registration state without persisting it.
  - [x] Implement `finish_registration` to accept stored registration state and a browser credential and return a validated `RpCredential` without database access.
  - [x] Implement `start_authentication` to return discoverable request options plus serializable authentication state without persisting it.
  - [x] Implement `finish_authentication` to accept stored authentication state, an `RpCredential`, and a browser assertion and return a validated credential-state update without database access.
  - [x] Add compile-time API tests that import every public ceremony type from the crate root.
  - [x] Add a dependency-boundary test that fails if the RP crate dependency graph contains `haya`, `axum`, `sqlx`, or `jsonwebtoken`.

- [x] Implement `PasskeyConfig` in `crates/haya-passkey-rp/src/config.rs`.
  - [x] Add `rp_id: String`.
  - [x] Add `rp_name: String`.
  - [x] Add `origins: Vec<url::Url>`.
  - [x] Add `challenge_ttl_secs: i64` with a fixed default of `300`.
  - [x] Add `allow_insecure_localhost: bool`, supplied by Haya only when development mode is enabled.
  - [x] Normalize origins to scheme, host, and explicit effective port before storing them.
  - [x] Reject origins containing a username, password, query, fragment, or non-root path.
  - [x] Reject IP-address RP IDs.
  - [x] Reject RP IDs containing a scheme, port, path, query, or fragment.
  - [x] Reject an origin whose host is neither the RP ID nor a subdomain ending in `.<rp_id>`.
  - [x] Reject non-HTTPS origins unless `allow_insecure_localhost` is true and the host is exactly `localhost`; reject all IP-address origins.
  - [x] Reject challenge TTL values below 60 seconds or above 600 seconds.
  - [x] Sort and deduplicate normalized origins.

- [x] Parse passkey enablement and RP settings in the root `src/main.rs`.
  - [x] Parse `PASSKEY_ENABLED` using the existing boolean environment-value convention.
  - [x] Require `PASSKEY_RP_ID` when passkeys are enabled.
  - [x] Default `PASSKEY_RP_NAME` to `SITE_NAME`.
  - [x] Require at least one comma-separated origin in `PASSKEY_RP_ORIGINS` when passkeys are enabled.
  - [x] Parse `PASSKEY_CHALLENGE_TTL_SECS` with a default of `300`.
  - [x] Pass `HAYA_DEV_MODE` into `PasskeyConfig::allow_insecure_localhost` rather than reading environment variables inside the RP crate.
  - [x] Validate the complete configuration by constructing `PasskeyRp` before opening the HTTP listener.
  - [x] Keep passkey state absent rather than partially initialized when passkeys are disabled.

- [x] Add passkey state to the root `src/state.rs` and `src/main.rs`.
  - [x] Import `PasskeyRp` from `haya_passkey_rp`.
  - [x] Add `pub passkey: Option<Arc<PasskeyRp>>` to `AppState`.
  - [x] Construct one immutable `PasskeyRp` during application bootstrap when passkeys are enabled.
  - [x] Set `AppState.passkey` to `None` when passkeys are disabled.
  - [x] Update every test `AppState` constructor to provide the new field explicitly.

- [x] Add focused RP-crate and Haya bootstrap configuration tests.
  - [x] Test in Haya that disabled passkeys require no RP variables.
  - [x] Test in Haya that enabled passkeys reject a missing RP ID.
  - [x] Test in Haya that enabled passkeys reject an empty origins list.
  - [x] Test in the RP crate that `https://app.example.com` is valid for RP ID `example.com`.
  - [x] Test in the RP crate that `https://example.com` is valid for RP ID `example.com`.
  - [x] Test in the RP crate that `https://example.net` is rejected for RP ID `example.com`.
  - [x] Test in the RP crate that `https://badexample.com` is rejected for RP ID `example.com`.
  - [x] Test in the RP crate that origin paths, queries, fragments, usernames, and passwords are rejected.
  - [x] Test in the RP crate that insecure production origins are rejected.
  - [x] Test in the RP crate that `http://localhost` is accepted only when `allow_insecure_localhost` is true and that IP-address origins remain rejected.
  - [x] Test challenge TTL lower and upper bounds.
  - [x] Test that duplicate normalized origins are removed.

### Acceptance criteria

- `cargo metadata` reports `haya` and unpublished `haya-passkey-rp` as members of one workspace.
- `cargo test --package haya-passkey-rp` runs without PostgreSQL, Axum, Haya application state, or environment variables.
- `cargo test --package haya` passes with passkeys disabled and no passkey environment variables.
- Startup tests prove enabled passkeys fail closed for every incomplete or invalid RP configuration.
- `AppState` contains either one fully validated `PasskeyRp` or `None`; no partially initialized state exists.
- The RP crate contains production `passkey-types`, `passkey-crypto`, and ES256 dependencies but no `webauthn-rs`, SQL, HTTP, JWT, or Haya application dependencies.

---

## Phase 2 — RP protocol primitives and deterministic verification

### Goal

Implement the security-critical, side-effect-free WebAuthn parsing and verification primitives before adding database or HTTP behavior.

### Overview

This phase implements the pure protocol engine entirely inside `haya-passkey-rp`. It turns typed browser responses into validated RP results without HTTP, SQL, environment access, or application state. Each parser must accept bounded byte slices, reject malformed data without panicking, and expose enough structured information for Haya to persist and orchestrate registration and authentication ceremonies.

### Rules

- Never verify a reconstructed `clientDataJSON`; hash the exact bytes received from the browser.
- Never trust the browser-provided `id`, `publicKey`, or `publicKeyAlgorithm` without matching authenticator-protected data.
- Use constant-time byte comparison for challenges and RP ID hashes.
- Reject unknown flag combinations, unsupported algorithms, unsupported attestation formats, and trailing malformed CBOR.
- Limit all attacker-controlled binary lengths before allocating or parsing nested data.
- Do not log raw client data, authenticator data, credential IDs, user handles, signatures, or public keys.

### Work items

- [x] Implement RP-owned credential and ceremony result types in `crates/haya-passkey-rp/src/credential.rs`.
  - [x] Define `RpCredential` with credential ID, user handle, COSE public key bytes, algorithm, signature counter, AAGUID, transports, backup eligibility, and backup state.
  - [x] Derive `Serialize` and `Deserialize` for database JSON storage.
  - [x] Implement a redacted `Debug` representation that excludes credential ID, user handle, and public key bytes.
  - [x] Add validation that credential IDs are non-empty and at most 1023 bytes.
  - [x] Add validation that user handles are non-empty and at most 64 bytes.
  - [x] Add validation that the algorithm is exactly ES256.
  - [x] Add serialization round-trip tests and redacted-debug tests.

- [x] Implement challenge generation and encoding.
  - [x] Generate exactly 32 random bytes using a cryptographically secure RNG.
  - [x] Return challenges as `passkey_types::Bytes` in WebAuthn options.
  - [x] Include raw challenge bytes in the serializable ceremony state returned to Haya and compare those raw bytes rather than their JSON encoding.
  - [x] Add a test generating multiple challenges and asserting the expected length and non-equality.
  - [x] Add a test proving base64url JSON serialization round-trips to the original raw bytes.

- [x] Implement collected-client-data parsing in `crates/haya-passkey-rp/src/client_data.rs`.
  - [x] Deserialize the exact `clientDataJSON` bytes into `CollectedClientData` while preserving the original bytes separately for hashing.
  - [x] Reject client data larger than 64 KiB before deserialization.
  - [x] Implement registration validation requiring type `webauthn.create`.
  - [x] Implement authentication validation requiring type `webauthn.get`.
  - [x] Decode the base64url challenge and compare it in constant time with the stored raw challenge.
  - [x] Normalize the client origin and require an exact match against one configured origin.
  - [x] Reject `crossOrigin: true`.
  - [x] Reject malformed JSON, malformed base64url, unknown ceremony type, wrong challenge, and wrong origin.
  - [x] Compute `SHA-256(clientDataJSON)` from the original bytes.
  - [x] Add table-driven positive and negative tests for every validation branch.

- [x] Implement bounded authenticator-data parsing in `crates/haya-passkey-rp/src/authenticator_data.rs`.
  - [x] Parse the 32-byte RP ID hash.
  - [x] Parse the flags byte into explicit UP, UV, BE, BS, AT, and ED booleans.
  - [x] Reject backup state when backup eligibility is false.
  - [x] Parse the big-endian 32-bit signature counter.
  - [x] Parse attested credential data only when the AT flag is present.
    - [x] Parse the 16-byte AAGUID.
    - [x] Parse the big-endian credential ID length.
    - [x] Reject zero-length and greater-than-1023-byte credential IDs.
    - [x] Parse exactly the declared credential ID bytes.
    - [x] Parse exactly one CBOR COSE key from the remaining attested-credential-data section.
  - [x] Parse extensions only when the ED flag is present and reject malformed extension CBOR.
  - [x] Reject fewer than 37 bytes of base authenticator data.
  - [x] Reject truncated AAGUID, credential length, credential ID, and COSE key input.
  - [x] Add deterministic parser tests for every flag and truncation boundary.
  - [x] Add fuzz-style property tests asserting arbitrary byte slices never panic.

- [x] Implement RP ID hash verification.
  - [x] Compute `SHA-256(rp_id.as_bytes())` through the selected `passkey-crypto` SHA-256 backend.
  - [x] Compare the computed hash with authenticator data in constant time.
  - [x] Add tests for matching RP IDs, wrong RP IDs, and one-byte hash mutations.

- [x] Implement ES256 COSE public-key validation and assertion verification.
  - [x] Decode the credential public key as a `passkey_crypto::CoseKey`.
  - [x] Require key type EC2, algorithm ES256, and curve P-256.
  - [x] Require exactly 32-byte X and Y coordinates.
  - [x] Reject private-key parameter `d` if it appears in RP credential material.
  - [x] Construct a `p256::ecdsa::VerifyingKey` from the uncompressed SEC1 point `0x04 || X || Y`.
  - [x] Parse assertion signatures as DER-encoded ECDSA signatures.
  - [x] Verify signatures over `authenticatorData || SHA-256(clientDataJSON)`.
  - [x] Add tests generated from the `passkey-rs` software authenticator for valid signatures.
  - [x] Add tests rejecting wrong keys, changed authenticator data, changed client-data hashes, malformed DER, high-length DER, and unsupported COSE algorithms.

- [x] Implement `none` attestation parsing and verification in `crates/haya-passkey-rp/src/attestation.rs`.
  - [x] Decode the attestation object as a bounded CBOR map.
  - [x] Require `fmt` to equal `none`.
  - [x] Require `attStmt` to be an empty map.
  - [x] Extract `authData` from the attestation object and parse it using the shared authenticator-data parser.
  - [x] Require UP, UV, and AT flags.
  - [x] Verify the RP ID hash.
  - [x] Require the credential ID from authenticator data to exactly match `rawId`.
  - [x] Require the credential type to be `public-key`.
  - [x] Validate and serialize the authenticator-protected COSE public key.
  - [x] Ignore browser-reported `publicKey` and `publicKeyAlgorithm` as sources of truth and reject them when present but inconsistent with parsed authenticator data.
  - [x] Return a validated `RpCredential` with initial counter and backup flags.
  - [x] Add tests accepting valid `none` attestation and rejecting packed, TPM, Android, Apple, U2F, malformed, and internally inconsistent objects.

- [x] Implement authentication assertion verification in `crates/haya-passkey-rp/src/assertion.rs`.
  - [x] Require credential type `public-key`.
  - [x] Require `rawId` to exactly match the stored credential ID.
  - [x] Validate client data as `webauthn.get`.
  - [x] Parse authenticator data and require UP and UV.
  - [x] Verify the RP ID hash.
  - [x] Require the returned user handle to exist for discoverable authentication.
  - [x] Require the returned user handle to exactly match the stored credential user handle.
  - [x] Verify the ES256 signature over the exact signed message.
  - [x] Apply signature-counter policy.
    - [x] Accept `stored = 0, returned = 0` for authenticators without counters.
    - [x] Accept a returned counter greater than the stored counter.
    - [x] Reject a non-zero returned counter less than or equal to a non-zero stored counter.
    - [x] Persist the maximum accepted counter.
  - [x] Update backup state from validated authenticator flags while preserving backup eligibility constraints.
  - [x] Return a validated credential-state update without mutating persistence directly.
  - [x] Add tests for valid counterless, incrementing-counter, rollback, user-handle mismatch, missing-user-handle, missing-UP, missing-UV, RP mismatch, and signature-failure cases.

- [x] Implement protocol errors in `crates/haya-passkey-rp/src/error.rs` and Haya response mapping in `src/error/mod.rs`.
  - [x] Define `RpError` variants detailed enough for RP-crate tests and broad Haya audit reason categories.
  - [x] Keep `RpError` independent of Axum status codes and Haya response types.
  - [x] Implement `From<RpError> for AuthError` or an equivalent root-package mapping at the Haya integration boundary.
  - [x] Map registration failures to one stable public `passkey_registration_failed` error code.
  - [x] Map authentication failures to one stable public `passkey_authentication_failed` error code.
  - [x] Keep parser, CBOR, COSE, challenge, origin, credential lookup, and signature details out of client responses.
  - [x] Add RP-crate tests for internal variants and Haya response tests proving all authentication protocol failures have the same status and public error shape.

### Acceptance criteria

- `cargo test --package haya-passkey-rp` proves that registration and authentication validate type, challenge, origin, cross-origin state, RP ID hash, flags, user handle, credential ID, algorithm, signature, and counter without starting Haya or PostgreSQL.
- Arbitrary authenticator-data byte slices do not panic in property tests.
- Only ES256 and `none` attestation are accepted.
- No RP credential type contains private-key material.
- Haya's `RpError` mapping tests prove public responses do not reveal which verification stage failed.

---

## Phase 3 — PostgreSQL schema and transactional repositories

### Goal

Persist public credentials and ceremony state in PostgreSQL with indexed lookup, strict constraints, one-use flows, and transaction-safe state transitions.

### Overview

This phase adds storage without exposing HTTP routes. Repository functions must make replay and multi-instance races impossible through row locks and conditional updates.

### Rules

- Never store active challenge state only in process memory.
- Never query credential IDs from inside JSON.
- Never consume a flow before its associated credential or session state is committed.
- Use parameterized SQL for every query.
- Keep all verification-result writes inside explicit transactions.

### Work items

- [x] Add a reversible migration for WebAuthn credentials and flows.
  - [x] Add `web_authn_credential_id bytea null` to `auth.mfa_factors`.
  - [x] Add a unique partial index on `web_authn_credential_id` for WebAuthn factors.
  - [x] Add a check constraint requiring WebAuthn factors to have both `web_authn_credential_id` and `web_authn_credential`.
  - [x] Add a check constraint preventing non-WebAuthn factors from populating `web_authn_credential_id`.
  - [x] Create `auth.web_authn_flows` with UUID ID, nullable user ID, purpose, challenge, state, friendly name, attempts, expiry, consumed timestamp, and audit timestamps.
  - [x] Add a purpose check allowing only `registration` and `authentication`.
  - [x] Add a check requiring registration flows to have a user ID.
  - [x] Add a check requiring a 32-byte challenge.
  - [x] Add indexes on `expires_at`, `user_id`, and active-flow lookup.
  - [x] Add `ON DELETE CASCADE` from flow user IDs to `auth.users`.
  - [x] Add a `-- !DOWN` section that removes indexes, the flow table, constraints, and the credential-ID column in reverse dependency order.

- [x] Add Haya database row types and repository code in `src/auth/passkey_repository.rs`.
  - [x] Export the repository module from `src/auth/mod.rs` as `pub(crate)`.
  - [x] Keep `sqlx` and every PostgreSQL row type out of `haya-passkey-rp`.
  - [x] Define `WebAuthnFactorRow` with factor metadata, credential ID, serialized `RpCredential`, and timestamps.
  - [x] Define `WebAuthnFlowRow` with purpose, raw challenge, state, ownership, attempts, expiry, and consumption state.
  - [x] Deserialize credential JSON into `RpCredential` and map malformed stored data to an internal error.
  - [x] Add tests for valid and malformed row-to-domain conversion.

- [x] Implement registration-flow repository functions.
  - [x] Insert a registration flow with user ID, challenge, serialized state, friendly name, and calculated expiry.
  - [x] Delete older active registration flows for the same user before inserting a new flow.
  - [x] Lock a registration flow by ID with `SELECT ... FOR UPDATE` during completion.
  - [x] Require matching user ownership, unconsumed state, registration purpose, unexpired time, and attempts below the limit.
  - [x] Increment attempts atomically before protocol verification.
  - [x] Insert the verified WebAuthn factor and mark the flow consumed in the same transaction.
  - [x] Convert unique credential-ID conflicts into a safe registration failure.

- [x] Implement authentication-flow repository functions.
  - [x] Insert an authentication flow without a user ID.
  - [x] Lock an authentication flow by ID with `SELECT ... FOR UPDATE` during completion.
  - [x] Require unconsumed state, authentication purpose, unexpired time, and attempts below the limit.
  - [x] Increment attempts atomically before protocol verification.
  - [x] Resolve a verified WebAuthn factor by exact raw credential ID.
  - [x] Lock the factor row before validating and updating signature-counter state.
  - [x] Update serialized `RpCredential`, `last_challenged_at`, and `updated_at` after successful verification.
  - [x] Mark the flow consumed in the same transaction as the factor update.

- [x] Implement flow cleanup helpers.
  - [x] Delete expired flows.
  - [x] Delete consumed flows older than one hour.
  - [x] Bound each cleanup call to a fixed batch size.
  - [x] Invoke cleanup opportunistically after successful flow creation without blocking the response on cleanup failure.
  - [x] Add tests proving active flows are retained and expired or old consumed flows are removed.

- [x] Add PostgreSQL integration tests for schema and concurrency.
  - [x] Apply the migration to an empty test database.
  - [x] Roll the migration down and up again successfully.
  - [x] Insert and fetch a WebAuthn factor with binary credential ID and JSON credential state.
  - [x] Prove duplicate credential IDs are rejected across different users.
  - [x] Prove a registration flow cannot be completed by a different user.
  - [x] Prove an expired flow cannot be consumed.
  - [x] Prove a consumed flow cannot be consumed again.
  - [x] Run two concurrent completion transactions and prove exactly one can consume the same flow.
  - [x] Prove deleting a user cascades to WebAuthn factors and registration flows.

### Acceptance criteria

- Migrations apply and roll back in automated database tests.
- Credential lookup uses the indexed binary credential-ID column.
- Concurrent completion attempts result in exactly one successful flow consumption.
- Credential state update and flow consumption are atomic.
- Expired, consumed, wrong-purpose, and wrong-owner flows are rejected by repository tests.

---

## Phase 4 — Authenticated passkey registration

### Goal

Allow an authenticated Haya user to create a discoverable, user-verified passkey and store its public credential as a verified WebAuthn factor.

### Overview

Registration is a two-request ceremony. The options request requires recent reauthentication, and the verification request is bound to the same authenticated user through the persisted flow.

### Rules

- Registration never creates a new Haya user.
- Registration requires an active bearer session and the existing reauthentication policy.
- Registration options exclude every existing credential owned by the user.
- A factor is inserted only after complete RP verification succeeds.
- Registration failures must not leave unverified factor rows behind.

### Work items

- [x] Add Haya registration HTTP DTOs in `src/public/handler/passkey.rs` using types re-exported by `haya-passkey-rp`.
  - [x] Define `PasskeyRegistrationOptionsRequest` with friendly name, current password, and reauthentication token.
  - [x] Define `PasskeyRegistrationOptionsResponse` with flow ID, expiry, and the RP crate's creation-options type.
  - [x] Define `PasskeyRegistrationVerifyRequest` with flow ID and the RP crate's created-credential type.
  - [x] Define `PasskeyFactorResponse` containing only ID, friendly name, status, AAGUID, transports, creation time, update time, and last challenge time.
  - [x] Keep flow IDs, reauthentication fields, factor IDs, and database timestamps out of `haya-passkey-rp` ceremony types.
  - [x] Add JSON serialization tests matching browser-compatible camelCase WebAuthn fields and base64url bytes.

- [x] Implement registration option generation in `crates/haya-passkey-rp` through `PasskeyRp::start_registration`.
  - [x] Accept an opaque user handle, display name, account name, and excluded credential descriptors as explicit method inputs without depending on Haya user types.
  - [x] In the Haya handler, pass the authenticated user UUID bytes as the stable opaque user handle.
  - [x] Reject any supplied user handle outside the 1–64 byte range.
  - [x] In the Haya handler, pass the user's email when available as the display-only account name; otherwise pass the user UUID string.
  - [x] Generate a 32-byte challenge.
  - [x] Set the RP entity ID and name from validated configuration.
  - [x] Advertise only `PublicKeyCredentialType::PublicKey` with ES256.
  - [x] Set timeout to 300,000 milliseconds.
  - [x] Set resident key to `Required` and `requireResidentKey` to true.
  - [x] Set user verification to `Required`.
  - [x] Set attestation conveyance to `None`.
  - [x] Populate `excludeCredentials` from the credential descriptors supplied by Haya after it queries all existing WebAuthn credentials owned by the user.
  - [x] Return serializable registration state containing the exact raw challenge alongside the creation options without performing persistence.

- [x] Implement registration handlers in `src/public/handler/passkey.rs`.
  - [x] Add `registration_options` using `State<AppState>`, `ConnectInfo`, `AuthUser`, and typed JSON extraction.
  - [x] Return the stable disabled-feature error when `AppState.passkey` is absent.
  - [x] Reuse `session::require_reauthentication` with current password or reauthentication token.
  - [x] Normalize friendly names using the existing MFA naming rules.
  - [x] Enforce friendly-name uniqueness across all factors for the user.
  - [x] Enforce a maximum of 10 passkeys per user.
  - [x] Call `PasskeyRp::start_registration`, persist its returned state and exact challenge, and only then return its creation options.
  - [x] Add `registration_verify` using `State<AppState>`, `ConnectInfo`, `AuthUser`, and typed JSON extraction.
  - [x] Lock and validate the flow before running RP verification.
  - [x] Verify the complete registration ceremony through the RP service.
  - [x] Insert a verified `webauthn` factor with credential ID, credential JSON, AAGUID, and timestamps.
  - [x] Consume the flow in the same transaction as factor insertion.
  - [x] Return the sanitized factor response.

- [x] Register routes in `src/public/handler/mod.rs` and `src/public/router.rs`.
  - [x] Export `handler::passkey`.
  - [x] Add `POST /passkeys/register/options`.
  - [x] Add `POST /passkeys/register/verify`.
  - [x] Ensure both routes use the existing router body limit, timeout, tracing, and CORS layers.

- [x] Add registration rate limits and audit events.
  - [x] Rate-limit registration option creation per user and IP.
  - [x] Rate-limit registration verification failures per flow and IP.
  - [x] Record `passkey_enrollment_started` after flow persistence.
  - [x] Record `passkey_enrollment_succeeded` after factor insertion.
  - [x] Record `passkey_enrollment_failed` with a broad reason category and without credential payloads.
  - [x] Add tests asserting audit payloads contain user ID and factor ID where available but exclude challenges, raw credential IDs, keys, client data, and signatures.

- [x] Add registration handler and integration tests.
  - [x] Test that unauthenticated registration option requests are rejected.
  - [x] Test that stale sessions are rejected through `AuthUser`.
  - [x] Test that recent reauthentication is required.
  - [x] Test that generated options contain the configured RP, ES256, required resident key, required UV, and `none` attestation.
  - [x] Test that existing user credentials appear in `excludeCredentials`.
  - [x] Complete a registration using the `passkey-rs` software client and authenticator.
  - [x] Test that the stored credential contains only public material.
  - [x] Test wrong challenge, wrong origin, wrong RP ID, wrong user, malformed attestation, unsupported algorithm, duplicate credential ID, expired flow, and replayed flow.
  - [x] Test that every failed completion leaves the factor count unchanged.

### Acceptance criteria

- An authenticated and recently reauthenticated user can complete registration with the `passkey-rs` software authenticator.
- Registration produces one verified `webauthn` factor containing indexed public credential state.
- Invalid or replayed registration cannot create or modify a factor.
- Registration options always require discoverability and user verification and advertise only ES256.
- Automated tests prove that sensitive WebAuthn values are absent from responses, logs, and audit payloads.

---

## Phase 5 — Discoverable passkey authentication and Haya session issuance

### Goal

Authenticate users without an email or username by verifying a discoverable WebAuthn assertion and issuing the existing Haya token response.

### Overview

Authentication options are public and contain no account-specific credential list. Assertion completion resolves the account through the credential ID and verified user handle, updates credential state atomically, and creates an `aal2` session.

### Rules

- Do not accept an email, username, or user ID in the authentication options request.
- Do not reveal whether a credential ID or user handle exists.
- Do not issue a session until signature, origin, RP ID, user presence, user verification, user handle, counter, and user status all pass.
- Do not send a successfully verified passkey through the TOTP pending-login flow.
- Use the existing token response, refresh-token, client-context, and session persistence behavior.

### Work items

- [x] Add Haya authentication HTTP DTOs in `src/public/handler/passkey.rs` using types re-exported by `haya-passkey-rp`.
  - [x] Define an empty `PasskeyAuthenticationOptionsRequest` that rejects unknown identity fields.
  - [x] Define `PasskeyAuthenticationOptionsResponse` with flow ID, expiry, and the RP crate's request-options type.
  - [x] Define `PasskeyTokenGrantRequest` with flow ID and the RP crate's authenticated-credential type.
  - [x] Keep flow IDs, client context, token responses, and Haya user identifiers out of `haya-passkey-rp` ceremony types.
  - [x] Add browser-compatible JSON serialization and deserialization tests.

- [x] Implement discoverable authentication option generation in `crates/haya-passkey-rp` through `PasskeyRp::start_authentication`.
  - [x] Generate a 32-byte challenge.
  - [x] Set timeout from validated challenge TTL in milliseconds, defaulting to 300,000 milliseconds.
  - [x] Set the configured RP ID.
  - [x] Omit `allowCredentials`.
  - [x] Set user verification to `Required`.
  - [x] Return serializable authentication state containing the exact raw challenge alongside request options without performing persistence.

- [x] Implement the public authentication-options handler.
  - [x] Add `authentication_options` in `src/public/handler/passkey.rs`.
  - [x] Return the stable disabled-feature error when `AppState.passkey` is absent.
  - [x] Extract client IP and user agent without accepting bearer identity as ceremony input.
  - [x] Call `PasskeyRp::start_authentication`.
  - [x] Persist its returned authentication state and exact challenge as an anonymous authentication flow before returning options.
  - [x] Return the typed options response.
  - [x] Rate-limit option creation per IP.

- [x] Add passkey token-grant dispatch in `src/public/handler/token.rs`.
  - [x] Add `passkey` to the supported `grant_type` match.
  - [x] Deserialize the body into `PasskeyTokenGrantRequest`.
  - [x] Pass client IP and user agent into passkey completion.
  - [x] Return `TokenGrantResponse::Token` on success.
  - [x] Return the same public authentication error for unknown credentials and invalid assertions.

- [x] Implement transactional assertion completion.
  - [x] Lock and validate the authentication flow.
  - [x] Increment the flow attempt count.
  - [x] Resolve and lock the verified WebAuthn factor by raw credential ID.
  - [x] Deserialize and validate the stored `RpCredential`.
  - [x] Verify the complete assertion through the RP service.
  - [x] Derive the user UUID from the verified user handle bytes.
  - [x] Require the derived user UUID to match the factor owner.
  - [x] Load the full Haya `User` row.
  - [x] Reject deleted users.
  - [x] Reject users whose `banned_until` is in the future.
  - [x] Persist the updated signature counter and backup state.
  - [x] Update `last_challenged_at`.
  - [x] Consume the flow atomically with the credential update.

- [x] Issue a passkey-authenticated Haya session.
  - [x] Refactor `src/auth/session.rs` to expose a transaction-aware session issuance function that accepts an existing PostgreSQL transaction.
  - [x] Keep existing session issuance functions as wrappers that create and commit their own transaction.
  - [x] Create the passkey session in the same transaction as credential-state update and flow consumption.
  - [x] Set AAL to `aal2`.
  - [x] Set `factor_id` to the WebAuthn factor ID.
  - [x] Set AMR methods to exactly `webauthn`.
  - [x] Preserve client IP and user agent in the session.
  - [x] Build the final token response while the transaction can still roll back, commit atomically, and return it only after commit succeeds.

- [x] Add authentication rate limits and audit events.
  - [x] Rate-limit assertion completion per flow and IP.
  - [x] Record failures against a credential-independent IP key.
  - [x] Clear applicable failure limits after successful authentication.
  - [x] Record `passkey_login_succeeded` with user ID, factor ID, and client IP.
  - [x] Record `passkey_login_failed` with only a broad reason category and client IP.
  - [x] Add tests proving failure audit events cannot distinguish unknown credential from bad signature.

- [x] Rename TOTP-specific factor helpers to prevent passkey coupling.
  - [x] Rename `verified_factors_by_user_id` to `verified_totp_factors_by_user_id`.
  - [x] Rename TOTP-only factor lookup and listing helpers to include `totp` in their names.
  - [x] Update password, OIDC, verify, and MFA call sites.
  - [x] Add regression tests proving passkey factors do not trigger `PendingMfaResponse` in password or OIDC flows.
  - [x] Add regression tests proving verified TOTP factors continue to trigger the existing pending-MFA flow.

- [x] Add end-to-end authentication tests using the `passkey-rs` software client and authenticator.
  - [x] Register a credential through Haya before authentication.
  - [x] Request discoverable authentication options without an identity.
  - [x] Produce a signed assertion through the software authenticator.
  - [x] Exchange the assertion through `POST /token?grant_type=passkey`.
  - [x] Decode the returned JWT and assert `aal == "aal2"`.
  - [x] Assert the JWT AMR contains exactly `webauthn`.
  - [x] Assert the persisted session references the WebAuthn factor.
  - [x] Assert client IP and user agent are persisted.
  - [x] Assert the refresh token can be exchanged through the existing refresh-token grant.
  - [x] Test wrong challenge, wrong origin, wrong RP ID, missing UP, missing UV, missing user handle, wrong user handle, malformed signature, wrong key, expired flow, replayed flow, and counter rollback.
  - [x] Test that assertion replay does not create a second session.
  - [x] Test that banned and deleted users cannot receive sessions.
  - [x] Test that concurrent assertion completion creates exactly one session.

### Acceptance criteria

- A discoverable software-authenticator credential can authenticate without an email or username.
- Successful authentication returns the existing Haya token response with an `aal2` JWT and `webauthn` AMR.
- Credential-state update, flow consumption, and session creation are atomic.
- Unknown credentials, invalid signatures, wrong user handles, and all other assertion failures share one public error shape.
- Replay and concurrent-completion tests prove that one assertion creates at most one session.
- Existing password, OIDC, TOTP, refresh-token, and JWT behavior remains covered and unchanged.

---

## Phase 6 — Passkey listing, deletion, capability discovery, and account safety

### Goal

Expose authenticated passkey management without leaking credential material or allowing users to unintentionally remove their final usable sign-in method.

### Overview

This phase adds sanitized management endpoints and advertises passkey capability through the existing settings response. Deletion revokes factor-backed sessions and enforces account-recovery safety.

### Rules

- Management endpoints operate only on factors owned by the authenticated user.
- Management responses never include credential IDs, public keys, counters, user handles, or serialized credential state.
- Removing a passkey requires an `aal2` session or successful existing reauthentication.
- The final usable sign-in method cannot be removed.
- Deleting a passkey revokes every session that references that factor.

### Work items

- [x] Implement sanitized passkey listing.
  - [x] Query only verified WebAuthn factors owned by the authenticated user.
  - [x] Order factors by creation time and ID for deterministic responses.
  - [x] Map rows to `PasskeyFactorResponse` without credential material.
  - [x] Add `GET /passkeys` to `src/public/router.rs`.
  - [x] Add response tests proving sensitive fields are absent.

- [x] Implement final-sign-in-method detection.
  - [x] Treat a non-empty password hash as one usable sign-in method.
  - [x] Count other verified WebAuthn factors as usable sign-in methods.
  - [x] Do not count TOTP as a primary sign-in method.
  - [x] Do not count OIDC identity as a fallback unless an active configured provider maps to that identity.
  - [x] Reject deletion when the selected passkey is the only usable sign-in method.
  - [x] Lock the user and owned passkey factors while evaluating and deleting to prevent concurrent last-method removal.
  - [x] Add tests for password-plus-passkey, two-passkey, passkey-only, TOTP-plus-passkey, and active-OIDC-plus-passkey accounts.

- [x] Implement authenticated passkey deletion.
  - [x] Add a typed delete request supporting current password or reauthentication token.
  - [x] Require `aal2` or reuse `session::require_reauthentication` before deletion.
  - [x] Require the factor to be an owned verified WebAuthn factor.
  - [x] Enforce final-sign-in-method protection inside the deletion transaction.
  - [x] Delete sessions whose `factor_id` matches the passkey.
  - [x] Delete the factor.
  - [x] Update the owning user's `updated_at` timestamp.
  - [x] Commit all deletion effects atomically.
  - [x] Add `DELETE /passkeys/{id}` to `src/public/router.rs`.
  - [x] Record `passkey_deleted` with user ID and factor ID.

- [x] Advertise passkey capability in `src/public/handler/settings.rs`.
  - [x] Add `external.passkey` with the value `true` only when passkeys are enabled.
  - [x] Add `mfa.webauthn` with the value `true` only when passkeys are enabled.
  - [x] Preserve existing email, OIDC, and TOTP settings fields.
  - [x] Add settings response tests for enabled and disabled configurations.

- [x] Make generic factor listing safe without changing TOTP enrollment behavior.
  - [x] Update `GET /factors` to return both TOTP and WebAuthn sanitized factor metadata.
  - [x] Keep `POST /factors` mapped only to TOTP enrollment for compatibility.
  - [x] Keep TOTP verification routes restricted to TOTP factors.
  - [x] Keep `/passkeys` responses specialized for passkey management clients.
  - [x] Add regression tests proving a passkey cannot be supplied to TOTP verification or deletion internals.

- [x] Add passkey management integration tests.
  - [x] List multiple passkeys and verify stable ordering.
  - [x] Verify one user cannot list or delete another user's passkey.
  - [x] Verify deletion without recent reauthentication is rejected.
  - [x] Verify deletion with `aal2` succeeds.
  - [x] Verify deletion revokes sessions tied to the factor.
  - [x] Verify deletion of one of two passkeys succeeds.
  - [x] Verify deletion of the only passkey succeeds when a password exists.
  - [x] Verify deletion of the only passkey fails when no other usable sign-in method exists.
  - [x] Verify a deleted credential can no longer authenticate.
  - [x] Verify settings advertise passkeys only while enabled.

### Acceptance criteria

- Authenticated users can list only their own sanitized passkey metadata.
- Passkey deletion is atomic, reauthenticated, ownership-checked, and session-revoking.
- Automated tests prevent deletion of the final usable sign-in method.
- Settings responses accurately reflect whether the RP is enabled.
- Existing generic factor and TOTP endpoints remain compatible and type-safe.

---

## Phase 7 — Abuse resistance, regression coverage, and automated release gates

### Goal

Complete protocol hardening, prove compatibility through software-authenticator end-to-end tests, and make passkey security checks mandatory in the repository’s automated validation.

### Overview

This phase consolidates negative tests, parser robustness, rate-limit behavior, transactional races, and dependency-policy checks into repeatable automated gates.

### Rules

- Every security regression must have a test that fails before the fix and passes after it.
- No test may require a human authenticator, browser interaction, QR scan, biometric prompt, or manual database setup.
- Phase 7 passkey integration tests must use the `passkey-rs` software client/authenticator and an isolated PostgreSQL test database.
- Logs captured by tests must never contain sensitive WebAuthn byte strings.
- Clippy warnings are release-blocking.

### Work items

- [x] Add direct `passkey-rs` software-peer dependencies only to the root package's `[dev-dependencies]`.
  - [x] Add the narrowest compatible `passkey-client` and `passkey-authenticator` dev dependencies with testable Tokio support to the root `Cargo.toml`.
  - [x] Keep software-client and software-authenticator dependencies out of `crates/haya-passkey-rp/Cargo.toml` normal dependencies.
  - [x] Add an in-memory authenticator credential store used only by root integration tests.
  - [x] Add deterministic test user validation that always reports user presence and user verification.
  - [x] Add helpers that convert Haya option responses into software-client calls and return browser-shaped credential JSON.

- [x] Build a reusable Phase 7 passkey integration-test fixture.
  - [x] Start Haya with an isolated database, fixed RP ID, fixed secure-context-equivalent localhost origin, and passkeys enabled.
  - [x] Create confirmed Haya users through database fixtures.
  - [x] Create bearer sessions for authenticated registration.
  - [x] Execute complete registration and authentication ceremonies through public HTTP endpoints.
  - [x] Clean up users, flows, factors, sessions, rate-limit rows, and the isolated database after each test.
  - [x] Ensure Phase 7 tests can run concurrently without sharing databases, credential stores, or flow IDs.

- [x] Add a complete negative-protocol test matrix.
  - [x] Mutate each byte of a valid challenge and prove verification fails.
  - [x] Mutate the origin and prove verification fails.
  - [x] Mutate the RP ID hash and prove verification fails.
  - [x] Remove and alter UP, UV, AT, BE, and BS flags and assert policy behavior.
  - [x] Truncate authenticator data at every structural boundary.
  - [x] Supply oversized client data, credential IDs, user handles, CBOR maps, and signatures.
  - [x] Supply duplicate and malformed COSE parameters.
  - [x] Supply unsupported algorithms and curves.
  - [x] Supply invalid ECDSA DER encodings.
  - [x] Replay registration and authentication responses.
  - [x] Complete flows after expiry and after attempt exhaustion.
  - [x] Swap valid responses between two flows and prove challenge binding rejects them.
  - [x] Submit a response from outside the configured exact-origin set and prove origin validation rejects it.
  - [x] Swap valid credentials between two users and prove user-handle and ownership checks reject them.

- [x] Add abuse and rate-limit integration tests.
  - [x] Exhaust registration-options limits for one user and IP and assert HTTP 429.
  - [x] Exhaust registration-verification attempts and assert the flow becomes unusable.
  - [x] Exhaust authentication-options limits for one IP and assert HTTP 429.
  - [x] Exhaust assertion-verification attempts and assert the flow becomes unusable.
  - [x] Prove a successful authentication clears applicable transient failure limits.
  - [x] Prove rate-limit keys and audit events do not contain raw credential IDs or user handles.

- [x] Add concurrency and atomicity regression tests.
  - [x] Race two registrations using the same credential ID and prove one factor is stored.
  - [x] Race two verifications of one registration flow and prove one factor is stored.
  - [x] Race two assertions for one authentication flow and prove one session is stored.
  - [x] Race two deletions of the final two usable passkeys and prove at least one usable method remains.
  - [x] Inject a session-insert failure and prove credential counter and flow consumption roll back.
  - [x] Inject a credential-update failure and prove no session is created.

- [x] Add sensitive-data leakage tests.
  - [x] Capture tracing output for successful and failed ceremonies.
  - [x] Assert logs do not contain challenge base64url, credential ID base64url, user handle base64url, client-data JSON, authenticator-data bytes, public-key material, or signatures.
  - [x] Serialize every public passkey response and assert stored credential fields are absent.
  - [x] Inspect audit payloads and assert only approved IDs and broad reason categories are present.
  - [x] Assert `Debug` output for RP credentials and flows is redacted.

- [x] Add workspace dependency and feature-policy tests.
  - [x] Add an automated workspace dependency-tree check that fails if `webauthn-rs` appears in any package.
  - [x] Add an RP-crate dependency-tree check that fails if `haya`, `axum`, `sqlx`, `jsonwebtoken`, `passkey-client`, or `passkey-authenticator` appears in normal dependencies.
  - [x] Add a root-package dependency-tree check that permits `passkey-client` and `passkey-authenticator` only as dev dependencies.
  - [x] Add an RP-crate compile test proving only ES256 is emitted in registration options.
  - [x] Add an RP-crate compile/test assertion that `passkey-types` serializes WebAuthn bytes as base64url strings.

- [ ] Add mandatory workspace formatting, package tests, integration tests, and lint validation.
  - [x] Run `cargo +nightly fmt --all -- --check` and fix all formatting failures.
  - [x] Run `cargo test --quiet --package haya-passkey-rp` and fix all protocol-crate failures.
  - [x] Run `cargo test --quiet --package haya` and fix all application-package failures.
  - [ ] Run PostgreSQL integration tests for the root `haya` package with `DATABASE_URL` configured and fix passkey-caused failures.
  - [x] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and fix all workspace lints.
  - [x] Add RP-crate unit tests, root PostgreSQL integration tests, dependency-policy checks, nightly formatting, and strict workspace Clippy commands to the repository CI workflow.

### Acceptance criteria

- All registration, authentication, management, replay, malformed-input, rate-limit, atomicity, and leakage tests run without manual interaction.
- The `passkey-rs` software client/authenticator completes the same public HTTP ceremonies expected from a browser.
- Automated dependency checks prevent accidental introduction of `webauthn-rs`, reverse dependencies from the RP crate into Haya, or production client/authenticator code.
- `cargo fmt --all -- --check`, both package test suites, PostgreSQL integration tests, and strict workspace Clippy all pass in CI.
- No captured response, log, audit payload, or debug representation exposes protected WebAuthn material.
