-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_jwk
(
    pk SERIAL PRIMARY KEY,
    sid VARCHAR(255) NOT NULL,
    kid VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    keydata TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- !DOWN
