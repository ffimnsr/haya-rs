-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_authentication_request
(
    challenge VARCHAR(40) NOT NULL,
    requested_scope TEXT NOT NULL,
    verifier VARCHAR(40) NOT NULL,
    csrf VARCHAR(40) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    request_url TEXT NOT NULL,
    skip boolean NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    authenticated_at TIMESTAMPTZ,
    oidc_context TEXT NOT NULL,
    login_session_id VARCHAR(40),
    requested_at_audience TEXT DEFAULT '',
    CONSTRAINT hydra_oauth2_authentication_request_pkey PRIMARY KEY (challenge),
    CONSTRAINT hydra_oauth2_authentication_request_client_id_fk FOREIGN KEY (client_id)
        REFERENCES public.hydra_client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT hydra_oauth2_authentication_request_login_session_id_fk FOREIGN KEY (login_session_id)
        REFERENCES public.hydra_oauth2_authentication_session (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

CREATE INDEX hydra_oauth2_authentication_request_cid_idx
    ON public.hydra_oauth2_authentication_request USING btree
    (client_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_authentication_request_login_session_id_idx
    ON public.hydra_oauth2_authentication_request USING btree
    (login_session_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX hydra_oauth2_authentication_request_sub_idx
    ON public.hydra_oauth2_authentication_request USING btree
    (subject ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE UNIQUE INDEX hydra_oauth2_authentication_request_veri_idx
    ON public.hydra_oauth2_authentication_request USING btree
    (verifier ASC NULLS LAST)
    TABLESPACE pg_default;
-- !DOWN
