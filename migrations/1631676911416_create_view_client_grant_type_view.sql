-- # Put the your SQL below migration seperator.
-- !UP
CREATE OR REPLACE VIEW public.view_client_grant_type
 AS
 SELECT c.id AS client_id,
    c.client_secret,
    c.owner,
    c.audience,
    c.created_at,
    c.updated_at,
    string_agg(t.name::text, ','::text) AS grants
   FROM client c
     JOIN client_grant_type m ON c.id = m.client_id
     JOIN grant_type t ON m.grant_type_id = t.id
  GROUP BY c.id;

ALTER TABLE public.view_client_grant_type
    OWNER TO postgres;


-- !DOWN
DROP VIEW public.view_client_grant_type;
