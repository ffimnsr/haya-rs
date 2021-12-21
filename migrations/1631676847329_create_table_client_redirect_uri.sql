-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.client_redirect_uri
(
    client_id uuid NOT NULL,
    redirect_uri text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "fk_client_redirect_uri__client_Id" FOREIGN KEY (client_id)
        REFERENCES public.client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.client_redirect_uri
    OWNER to postgres;

CREATE UNIQUE INDEX IF NOT EXISTS ux_client_redirect_uri__client_id_response_uri
    ON public.client_redirect_uri USING btree
    (client_id ASC NULLS LAST, redirect_uri COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
DROP INDEX IF EXISTS public.ux_client_redirect_uri__client_id_response_uri;
DROP TABLE IF EXISTS public.client_redirect_uri;
