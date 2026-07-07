# Extends the official postgres:16 image with the pgsql-http extension
# (https://github.com/pramsey/pgsql-http), which docker/postgres/udf.sql uses to give
# tokenize()/reidentify() SQL functions a way to call the tokenization-api service over HTTP --
# see README.md's "Self-hosted Postgres/Redshift-alike" integration example.
#
# postgresql-16-http installs straight from apt with no extra repository setup: the base
# postgres:16 image already configures the PGDG repo (apt.postgresql.org) to install
# postgresql-16 itself, and that repo also carries this extension package.
FROM postgres:16

RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-16-http \
    && rm -rf /var/lib/apt/lists/*

# Baked into the image (rather than left as a docker-compose/docker-run bind mount) so the
# container is self-contained regardless of where the repo checkout lives on a given host --
# needed for deploy/ec2/postgres.service, which doesn't assume any particular checkout path.
COPY init.sql udf.sql /docker-entrypoint-initdb.d/
