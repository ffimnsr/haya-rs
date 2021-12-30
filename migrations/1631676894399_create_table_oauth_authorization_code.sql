-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.oauth_authorization_code
(
    jwt_id uuid NOT NULL,
    client_id uuid NOT NULL,
    request_id uuid NOT NULL,
	subject uuid NOT NULL,
    requested_scope text COLLATE pg_catalog."default" NOT NULL,
    granted_scope text COLLATE pg_catalog."default" NOT NULL,
    active boolean NOT NULL DEFAULT true,
    requested_audience text COLLATE pg_catalog."default" NOT NULL,
    granted_audience text COLLATE pg_catalog."default" NOT NULL,
    code_challenge character varying(60) COLLATE pg_catalog."default" NOT NULL,
    code_challenge_method character varying(5) COLLATE pg_catalog."default" NOT NULL,
    redirect_uri text COLLATE pg_catalog."default" NOT NULL,
    requested_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT pk_oauth_authorization_code__jwt_id PRIMARY KEY (jwt_id),
    CONSTRAINT fk_oauth_authorization_code__client_id FOREIGN KEY (client_id)
        REFERENCES public.client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.oauth_authorization_code
    OWNER to postgres;

-- !DOWN
DROP TABLE IF EXISTS public.oauth_authorization_code;
