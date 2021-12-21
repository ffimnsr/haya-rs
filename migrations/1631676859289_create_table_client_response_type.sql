-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.client_response_type
(
    client_id uuid NOT NULL,
    response_type_id integer NOT NULL,
    CONSTRAINT fk_client_response_type__client_id FOREIGN KEY (client_id)
        REFERENCES public.client (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT fk_client_response_type__response_type_id FOREIGN KEY (response_type_id)
        REFERENCES public.response_type (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.client_response_type
    OWNER to postgres;

CREATE UNIQUE INDEX IF NOT EXISTS ux_client_response_type__client_id_response_type_id
    ON public.client_response_type USING btree
    (client_id ASC NULLS LAST, response_type_id ASC NULLS LAST)
    TABLESPACE pg_default;

-- !DOWN
DROP INDEX IF EXISTS public.ux_client_response_type__client_id_response_type_id;
DROP TABLE IF EXISTS public.client_response_type;
