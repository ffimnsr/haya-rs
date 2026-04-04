alter table auth.mfa_factors
  add column if not exists last_verified_totp_step bigint null,
  add column if not exists enrollment_verify_attempts integer not null default 0,
  add column if not exists last_enrollment_verify_attempt_at timestamptz null;
