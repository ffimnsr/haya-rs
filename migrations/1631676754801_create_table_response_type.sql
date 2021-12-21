-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.response_type
(
    id smallint NOT NULL DEFAULT nextval('response_type_id_seq'::regclass),
    name character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT pk_response_type__id PRIMARY KEY (id),
    CONSTRAINT uc_response_type__name UNIQUE (name)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.response_type
    OWNER to postgres;

-- !DOWN
DROP TABLE IF EXISTS public.response_type;
