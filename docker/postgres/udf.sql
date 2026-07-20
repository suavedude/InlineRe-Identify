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

-- One-way (non-reversible) masking -- see com.delphix.dynamicmasking.onewaymasking. One
-- function per data shape, each hitting its own fixed /v1/mask/* endpoint (FULL-NAME-MASK,
-- CREDIT-CARD-MASK, EMAIL-MASK respectively) -- deliberately not a single generic mask(value)
-- whose behavior depends on process-wide config, since that's easy to point at the wrong column
-- (e.g. running an email through a scheme meant for names). Always available; no env var to set.
CREATE OR REPLACE FUNCTION mask_fullname(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/full-name',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_fullname failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION mask_creditcard(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/credit-card',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_creditcard failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION mask_email(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/email',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_email failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

-- Generic building-block schemes -- unlike mask_fullname()/mask_creditcard()/mask_email() above
-- (which each intelligently reshape their data: splitting "First Last" into two tokens, keeping
-- separators/domain in place), these are the raw, single-purpose schemes they're built from.
-- Useful directly for data that doesn't fit those three shapes -- e.g. mask_firstname() alone
-- for a column that's *only* a first name (no surname to split off), or mask_segmentmapping()
-- for a digits-only value with no separators to preserve.
CREATE OR REPLACE FUNCTION mask_firstname(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/first-name',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_firstname failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION mask_lastname(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/last-name',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_lastname failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION mask_dateshift(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/date-shift',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_dateshift failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION mask_segmentmapping(value text) RETURNS text AS $$
DECLARE
    resp http_response;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO resp FROM http_post(
        'http://tokenization-api:4051/v1/mask/segment-mapping',
        json_build_object('values', ARRAY[value])::text,
        'application/json'
    );
    IF resp.status <> 200 THEN
        RAISE EXCEPTION 'mask_segmentmapping failed (HTTP %): %', resp.status, resp.content;
    END IF;
    RETURN resp.content::json -> 'results' ->> 0;
END;
$$ LANGUAGE plpgsql STABLE;
