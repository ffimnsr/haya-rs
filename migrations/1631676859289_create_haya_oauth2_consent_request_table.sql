-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_consent_request
(
    challenge VARCHAR(40) NOT NULL,
    verifier VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    request_url TEXT NOT NULL,
    skip boolean NOT NULL,
    requested_scope TEXT NOT NULL,
    csrf VARCHAR(40) NOT NULL,
    authenticated_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    oidc_context TEXT NOT NULL,
    forced_subject_identifier VARCHAR(255) DEFAULT '',
    login_session_id VARCHAR(40),
    login_challenge VARCHAR(40),
    requested_at_audience TEXT DEFAULT '',
    acr TEXT DEFAULT '',
    context TEXT NOT NULL DEFAULT '{}',
    CONSTRAINT hydra_oauth2_consent_request_pkey PRIMARY KEY (challenge),
    CONSTRAINT hydra_oauth2_consent_request_client_id_fk FOREIGN KEY (client_id)
        REFERENCES public.hydra_client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT hydra_oauth2_consent_request_login_challenge_fk FOREIGN KEY (login_challenge)
        REFERENCES public.hydra_oauth2_authentication_request (challenge) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE SET NULL,
    CONSTRAINT hydra_oauth2_consent_request_login_session_id_fk FOREIGN KEY (login_session_id)
        REFERENCES public.hydra_oauth2_authentication_session (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE SET NULL
);

CREATE INDEX hydra_oauth2_consent_request_cid_idx
    ON public.hydra_oauth2_consent_request USING btree
    (client_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_consent_request_client_id_subject_idx
    ON public.hydra_oauth2_consent_request USING btree
    (client_id ASC NULLS LAST, subject ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_consent_request_login_challenge_idx
    ON public.hydra_oauth2_consent_request USING btree
    (login_challenge ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_consent_request_login_session_id_idx
    ON public.hydra_oauth2_consent_request USING btree
    (login_session_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_consent_request_sub_idx
    ON public.hydra_oauth2_consent_request USING btree
    (subject ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE UNIQUE INDEX hydra_oauth2_consent_request_veri_idx
    ON public.hydra_oauth2_consent_request USING btree
    (verifier ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
