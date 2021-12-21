-- # Put the your SQL below migration seperator.
-- !UP
CREATE OR REPLACE VIEW public.view_client_response_type
 AS
 SELECT c.id AS client_id,
    c.client_secret,
    c.owner,
    c.audience,
    c.created_at,
    c.updated_at,
    string_agg(t.name::text, ','::text) AS grants
   FROM client c
     JOIN client_response_type m ON c.id = m.client_id
     JOIN response_type t ON m.response_type_id = t.id
  GROUP BY c.id;

ALTER TABLE public.view_client_response_type
    OWNER TO postgres;

-- !DOWN
DROP VIEW public.view_client_response_type;
