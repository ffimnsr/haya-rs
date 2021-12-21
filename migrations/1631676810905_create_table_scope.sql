-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.scope
(
    id smallint NOT NULL DEFAULT nextval('scope_id_seq'::regclass),
    name character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT pk_scope__id PRIMARY KEY (id),
    CONSTRAINT uc_scope__name UNIQUE (name)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.scope
    OWNER to postgres;

-- !DOWN
DROP TABLE IF EXISTS public.scope;
