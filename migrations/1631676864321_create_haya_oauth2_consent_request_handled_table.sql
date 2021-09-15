-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_consent_request_handled
(
    challenge VARCHAR(40) NOT NULL,
    granted_scope TEXT NOT NULL,
    remember boolean NOT NULL,
    remember_for INTEGER NOT NULL,
    error TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_access_token TEXT NOT NULL,
    session_id_token TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ,
    was_used boolean NOT NULL,
    granted_at_audience TEXT DEFAULT '',
    handled_at TIMESTAMPTZ,
    CONSTRAINT hydra_oauth2_consent_request_handled_pkey PRIMARY KEY (challenge),
    CONSTRAINT hydra_oauth2_consent_request_handled_challenge_fk FOREIGN KEY (challenge)
        REFERENCES public.hydra_oauth2_consent_request (challenge) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

-- !DOWN
