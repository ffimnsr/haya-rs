-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_jti_blacklist
(
    signature VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hydra_oauth2_jti_blacklist_pkey PRIMARY KEY (signature)
);

CREATE INDEX hydra_oauth2_jti_blacklist_expiry
    ON public.hydra_oauth2_jti_blacklist USING btree
    (expires_at ASC NULLS LAST);

-- !DOWN
