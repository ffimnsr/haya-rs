-- # Put the your SQL below migration seperator.
-- !UP
CREATE OR REPLACE VIEW public.view_client_unite
 AS
 SELECT c.id AS client_id,
    c.client_secret,
    c.owner,
    c.audience,
    c.created_at,
    c.updated_at,
    string_agg(DISTINCT t1.name::text, ','::text) AS grants,
    string_agg(DISTINCT t2.name::text, ','::text) AS response_types,
    string_agg(DISTINCT t3.name::text, ','::text) AS scopes,
    string_agg(DISTINCT m4.redirect_uri, ','::text) AS redirect_uris
   FROM client c
     JOIN client_grant_type m1 ON c.id = m1.client_id
     JOIN grant_type t1 ON m1.grant_type_id = t1.id
     JOIN client_response_type m2 ON c.id = m2.client_id
     JOIN response_type t2 ON m2.response_type_id = t2.id
     JOIN client_scope m3 ON c.id = m3.client_id
     JOIN scope t3 ON m3.scope_id = t3.id
     JOIN client_redirect_uri m4 ON c.id = m4.client_id
  GROUP BY c.id;

ALTER TABLE public.view_client_unite
    OWNER TO postgres;

-- !DOWN
DROP VIEW public.view_client_unite;
