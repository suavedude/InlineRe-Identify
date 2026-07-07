#!/usr/bin/env bash
# Installed at /usr/local/bin/inline-reidentify-rebuild by user-data.sh. EC2 user-data only runs
# on first boot, so this is how you pick up new commits or an env-file change afterwards: SSH in
# and run it (optionally with a ref to move to; defaults to staying on the current branch's
# latest).
#
# Works whether APP_DIR is a git checkout (user-data.sh's `git clone` path) or a plain unzipped
# copy of the repo (no .git directory) -- in the latter case this just rebuilds from whatever
# files are already on disk and skips the git-pull step, since there's no remote to pull from.
#
# Usage: inline-reidentify-rebuild [git-ref]
set -euo pipefail

APP_DIR=/home/ec2-user/inline-reidentify
cd "$APP_DIR"

if [[ -d .git ]]; then
    REF="${1:-$(git rev-parse --abbrev-ref HEAD)}"
    git fetch --depth 1 origin "$REF"
    git reset --hard FETCH_HEAD
else
    REF="(no .git checkout -- files on disk as-is)"
    echo "No .git directory in $APP_DIR -- rebuilding from the files already on disk" \
         "(re-copy/unzip an updated checkout here first if you meant to pick up new code)." >&2
fi

./gradlew httpServerJar rawCryptoLibs
docker build -f Dockerfile.http-server -t inline-reidentify-tokenization-api:latest .
systemctl restart tokenization-api

# Only touch postgres if it was actually installed here (see README.md's "Deploying the REST API
# to EC2" -- postgres is an optional demo-data companion, not part of every deployment). Checking
# the unit *file*'s existence directly, rather than `systemctl list-unit-files postgres.service`,
# which isn't a reliable "is this installed" test -- it can exit 0 with zero matches.
if [[ -f /etc/systemd/system/postgres.service ]]; then
    docker build -t inline-reidentify-postgres:latest docker/postgres/
    systemctl restart postgres
fi

# demo-ui.service runs demo/server.py directly (no Docker image to rebuild) -- a restart alone
# picks up any code changes, since it re-reads its files from disk on every request/start.
if [[ -f /etc/systemd/system/demo-ui.service ]]; then
    systemctl restart demo-ui
fi

echo "Redeployed $REF. Tail logs: journalctl -u tokenization-api -f (and -u postgres/-u demo-ui, if deployed)"
