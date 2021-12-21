-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.client_scope
(
    client_id uuid NOT NULL,
    scope_id integer NOT NULL,
    CONSTRAINT fk_client_scope__client_id FOREIGN KEY (client_id)
        REFERENCES public.client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT fk_client_scope__scope_id FOREIGN KEY (scope_id)
        REFERENCES public.scope (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.client_scope
    OWNER to postgres;

CREATE UNIQUE INDEX IF NOT EXISTS ux_client_scope__client_id_scope_id
    ON public.client_scope USING btree
    (client_id ASC NULLS LAST, scope_id ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
DROP INDEX IF EXISTS public.ux_client_scope__client_id_scope_id;
DROP TABLE IF EXISTS public.client_scope;
