-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.client
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    client_secret character varying(255) COLLATE pg_catalog."default" NOT NULL,
    owner character varying(255) COLLATE pg_catalog."default" NOT NULL,
    audience character varying(255) COLLATE pg_catalog."default" NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT pk_client__id PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.client
    OWNER to postgres;

-- !DOWN
DROP TABLE IF EXISTS public.client;
