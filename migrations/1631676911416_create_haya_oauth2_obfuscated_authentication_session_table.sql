-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_obfuscated_authentication_session
(
    subject VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    subject_obfuscated VARCHAR(255) NOT NULL,
    CONSTRAINT hydra_oauth2_obfuscated_authentication_session_pkey PRIMARY KEY (subject, client_id),
    CONSTRAINT hydra_oauth2_obfuscated_authentication_session_client_id_fk FOREIGN KEY (client_id)
        REFERENCES public.hydra_client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX hydra_oauth2_obfuscated_authentication_session_so_idx
    ON public.hydra_oauth2_obfuscated_authentication_session USING btree
    (client_id ASC NULLS LAST, subject_obfuscated ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
