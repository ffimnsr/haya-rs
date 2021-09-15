-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_jwk
(
    pk INTEGER NOT NULL DEFAULT nextval('hydra_jwk_pk_seq'::regclass),
    sid VARCHAR(255) NOT NULL,
    kid VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    keydata TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hydra_jwk_pkey PRIMARY KEY (pk)
);

CREATE UNIQUE INDEX hydra_jwk_idx_id_uq
    ON public.hydra_jwk USING btree (sid ASC NULLS LAST, kid ASC NULLS LAST);

-- !DOWN
