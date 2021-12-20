-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_authentication_session
(
    id VARCHAR(40) NOT NULL,
    authenticated_at TIMESTAMPTZ,
    subject VARCHAR(255) NOT NULL,
    remember boolean NOT NULL DEFAULT false,
    CONSTRAINT hydra_oauth2_authentication_session_pkey PRIMARY KEY (id)
);

CREATE INDEX hydra_oauth2_authentication_session_sub_idx
    ON public.hydra_oauth2_authentication_session USING btree
    (subject ASC NULLS LAST);

-- !DOWN
