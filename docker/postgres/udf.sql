-- Wires tokenize()/reidentify() SQL functions to the tokenization-api service over HTTP, via the
-- pgsql-http extension installed in docker/postgres/Dockerfile. Runs after init.sql
-- (docker-entrypoint-initdb.d scripts execute in filename order, and "init.sql" sorts before
-- "udf.sql") -- see README.md's "Self-hosted Postgres/Redshift-alike" section for the pattern
-- this implements.
--
-- Each call is one HTTP round trip per row -- fine for interactive demos, but a table-wide UPDATE
-- should batch through /v1/tokenize directly (see scripts/test-http-api.sh) rather than calling
-- this function per row for bulk work.
CREATE EXTENSION IF NOT EXISTS http;

CREATE OR REPLACE FUNCTION tokenize(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/tokenize',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'tokenize failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION reidentify(token text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF token IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/reidentify',
        json_build_object('values', ARRAY[token])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'reidentify failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;
