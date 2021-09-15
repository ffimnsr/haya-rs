-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_logout_request
(
    challenge VARCHAR(36) NOT NULL,
    verifier VARCHAR(36) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    sid VARCHAR(36) NOT NULL,
    client_id VARCHAR(255),
    request_url TEXT NOT NULL,
    redir_url TEXT NOT NULL,
    was_used boolean NOT NULL DEFAULT false,
    accepted boolean NOT NULL DEFAULT false,
    rejected boolean NOT NULL DEFAULT false,
    rp_initiated boolean NOT NULL DEFAULT false,
    CONSTRAINT hydra_oauth2_logout_request_pkey PRIMARY KEY (challenge),
    CONSTRAINT hydra_oauth2_logout_request_client_id_fk FOREIGN KEY (client_id)
        REFERENCES public.hydra_client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

CREATE INDEX hydra_oauth2_logout_request_client_id_idx
    ON public.hydra_oauth2_logout_request USING btree
    (client_id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE UNIQUE INDEX hydra_oauth2_logout_request_veri_idx
    ON public.hydra_oauth2_logout_request USING btree
    (verifier ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
