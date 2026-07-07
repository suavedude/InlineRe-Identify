#!/usr/bin/env bash
# EC2 user-data bootstrap for the standalone tokenization REST API (TokenizationHttpServer),
# targeting Amazon Linux 2023. Installs Docker/git/a JDK, clones this repo, builds the jar and
# Dockerfile.http-server image on the instance itself, and installs+starts it as a systemd
# service (deploy/ec2/tokenization-api.service) so it survives reboots and restarts on crash.
#
# Paste this whole file (after filling in the CONFIGURE block below) as an EC2 instance's user
# data. See README.md's "Deploying the REST API to EC2" section for the full runbook -- IAM role
# permissions, security group rules, and why this uses KEY_SOURCE=KMS rather than a plaintext key.
set -euo pipefail

# ---- CONFIGURE -------------------------------------------------------------
# Where to clone this repo from -- must be reachable from the instance (public GitHub, a private
# repo with deploy credentials baked into the URL, CodeCommit, etc.). No remote is configured in
# this checkout yet, so there's no sane default to fall back to.
GIT_REPO_URL="${GIT_REPO_URL:-CHANGE_ME}"
GIT_REF="${GIT_REF:-main}"

# KMS envelope encryption is the real-deployment key source (see README.md) -- this script
# deliberately doesn't support KEY_SOURCE=PLAINTEXT, so a raw key never has to touch instance
# user-data (which is readable by anything with DescribeInstanceAttribute on this instance).
DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64="${DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64:-CHANGE_ME}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
AWS_REGION="${AWS_REGION:-}"
CRYPTO_PROVIDER="${CRYPTO_PROVIDER:-BCFIPS}"
CIPHER_ALGORITHM="${CIPHER_ALGORITHM:-AES-CBC-CTS}"
PORT="${PORT:-4051}"

# Also stand up the sample Postgres (docker/postgres) + tokenize()/reidentify() SQL functions on
# this same instance. This is demo/sample data only, not part of a real tokenization-api
# deployment -- leave this false unless you specifically want the SQL-level demo reachable here.
DEPLOY_DEMO_POSTGRES="${DEPLOY_DEMO_POSTGRES:-false}"

# Also run the browser demo UI (demo/server.py) on this instance, reachable at :4041 -- an
# always-on web UI, so leave this false unless you actually want it exposed here rather than run
# from your own machine (see README.md's "Browser demo UI" section).
DEPLOY_DEMO_UI="${DEPLOY_DEMO_UI:-false}"
# -----------------------------------------------------------------------------

if [[ "$GIT_REPO_URL" == "CHANGE_ME" || "$DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64" == "CHANGE_ME" ]]; then
    echo "user-data.sh: fill in GIT_REPO_URL and DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64 in the" \
         "CONFIGURE block before using this as EC2 user data." >&2
    exit 1
fi

dnf install -y docker git java-17-amazon-corretto-devel python3
systemctl enable --now docker

APP_DIR=/home/ec2-user/inline-reidentify
rm -rf "$APP_DIR"
git clone --branch "$GIT_REF" --depth 1 "$GIT_REPO_URL" "$APP_DIR"
cd "$APP_DIR"

./gradlew httpServerJar rawCryptoLibs
docker build -f Dockerfile.http-server -t inline-reidentify-tokenization-api:latest .

mkdir -p /etc/inline-reidentify
cat > /etc/inline-reidentify/tokenization-api.env <<EOF
KEY_SOURCE=KMS
DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64=${DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64}
KMS_KEY_ID=${KMS_KEY_ID}
AWS_REGION=${AWS_REGION}
CRYPTO_PROVIDER=${CRYPTO_PROVIDER}
CIPHER_ALGORITHM=${CIPHER_ALGORITHM}
PORT=${PORT}
EOF
chmod 600 /etc/inline-reidentify/tokenization-api.env

install -m 0644 "$APP_DIR/deploy/ec2/tokenization-api.service" /etc/systemd/system/tokenization-api.service
install -m 0755 "$APP_DIR/deploy/ec2/rebuild.sh" /usr/local/bin/inline-reidentify-rebuild

systemctl daemon-reload
systemctl enable --now tokenization-api

if [[ "$DEPLOY_DEMO_POSTGRES" == "true" ]]; then
    docker build -t inline-reidentify-postgres:latest docker/postgres/
    install -m 0644 "$APP_DIR/deploy/ec2/postgres.service" /etc/systemd/system/postgres.service
    systemctl daemon-reload
    systemctl enable --now postgres
fi

if [[ "$DEPLOY_DEMO_UI" == "true" ]]; then
    install -m 0644 "$APP_DIR/deploy/ec2/demo-ui.service" /etc/systemd/system/demo-ui.service
    systemctl daemon-reload
    systemctl enable --now demo-ui
fi
