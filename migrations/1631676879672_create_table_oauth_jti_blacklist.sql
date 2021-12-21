-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.oauth_jti_blacklist
(
    jwt_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT pk_oauth_jti_blacklist__jwt_id PRIMARY KEY (jwt_id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.oauth_jti_blacklist
    OWNER to postgres;

-- !DOWN
DROP TABLE IF EXISTS public.oauth_jti_blacklist;
