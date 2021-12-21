-- # Put the your SQL below migration seperator.
-- !UP
CREATE OR REPLACE VIEW public.view_client_scope
 AS
 SELECT c.id AS client_id,
    c.client_secret,
    c.owner,
    c.audience,
    c.created_at,
    c.updated_at,
    string_agg(t.name::text, ','::text) AS scopes
   FROM client c
     JOIN client_scope m ON c.id = m.client_id
     JOIN scope t ON m.scope_id = t.id
  GROUP BY c.id;

ALTER TABLE public.view_client_scope
    OWNER TO postgres;

-- !DOWN
DROP VIEW public.view_client_scope;
