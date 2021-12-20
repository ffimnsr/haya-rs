-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_oidc
(
    signature VARCHAR(255) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    granted_scope TEXT NOT NULL,
    form_data TEXT NOT NULL,
    session_data TEXT NOT NULL,
    subject VARCHAR(255) NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    requested_audience TEXT DEFAULT '',
    granted_audience TEXT DEFAULT '',
    challenge_id VARCHAR(40),
    CONSTRAINT hydra_oauth2_oidc_pkey PRIMARY KEY (signature),
    CONSTRAINT hydra_oauth2_oidc_challenge_id_fk FOREIGN KEY (challenge_id)
        REFERENCES public.hydra_oauth2_consent_request_handled (challenge) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT hydra_oauth2_oidc_client_id_fk FOREIGN KEY (client_id)
        REFERENCES public.hydra_client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

CREATE INDEX hydra_oauth2_oidc_challenge_id_idx
    ON public.hydra_oauth2_oidc USING btree
    (challenge_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_oidc_client_id_idx
    ON public.hydra_oauth2_oidc USING btree
    (client_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_oidc_request_id_idx
    ON public.hydra_oauth2_oidc USING btree
    (request_id ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
