-- # Put the your SQL below migration seperator.
-- !UP
CREATE EXTENSION IF NOT EXISTS "uuid-ossp"
    SCHEMA public
    VERSION "1.1";

-- !DOWN
DROP EXTENSION "uuid-ossp";
