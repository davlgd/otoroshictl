#!/usr/bin/env sh
# Local test script for otoroshictl challenge proxy.
# All configuration is done via environment variables.
# Uncomment and adjust the variables you need.

# ---------------------------------------------------------------------------
# Challenge protocol (state challenge V1/V2)
# ---------------------------------------------------------------------------

# Port the proxy listens on (default: 8080)
export OTOROSHI_CHALLENGE_FRONTEND_PORT=8080

# Backend host and port to forward requests to (default: 127.0.0.1:9000)
export OTOROSHI_CHALLENGE_BACKEND_HOST=127.0.0.1
# Backend port
export OTOROSHI_CHALLENGE_BACKEND_PORT=9000

# HMAC secret (required for V2). For asymmetric algos, provide the private key PEM
# or a path to the PEM file.
export OTOROSHI_CHALLENGE_SECRET="my-shared-secret"

# Set to any non-empty value to treat OTOROSHI_CHALLENGE_SECRET as base64-encoded
#export OTOROSHI_CHALLENGE_SECRET_BASE64=true

# Algorithm for verifying the incoming state challenge JWT
# (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 — default: HS512)
export OTOROSHI_CHALLENGE_ALG=HS512

# Public key PEM (or path) for asymmetric verification — extracted from
# OTOROSHI_CHALLENGE_SECRET if omitted
#export OTOROSHI_CHALLENGE_PUBLIC_KEY=/path/to/public.pem

# Secret (or private key PEM) used to sign the response JWT.
# Falls back to OTOROSHI_CHALLENGE_SECRET if not set.
export OTOROSHI_CHALLENGE_RESPONSE_SECRET="my-response-secret"

# Set to any non-empty value to treat OTOROSHI_CHALLENGE_RESPONSE_SECRET as base64-encoded
#export OTOROSHI_CHALLENGE_RESPONSE_SECRET_BASE64=true

# Algorithm for signing the response JWT (default: same as OTOROSHI_CHALLENGE_ALG)
export OTOROSHI_CHALLENGE_RESPONSE_ALG=HS512

# Header name carrying the incoming state challenge token (default: Otoroshi-State)
export OTOROSHI_CHALLENGE_REQ_HEADER_NAME=Otoroshi-State

# Header name for the response token sent back to Otoroshi (default: Otoroshi-State-Resp)
export OTOROSHI_CHALLENGE_RESP_HEADER_NAME=Otoroshi-State-Resp

# JWT token TTL in seconds (default: 30)
export OTOROSHI_CHALLENGE_TOKEN_TTL=30

# Request timeout toward the backend in seconds (default: 30)
#export OTOROSHI_CHALLENGE_TIMEOUT=30

# Set to any non-empty value to use V1 protocol (simple echo) instead of V2 JWT
#export OTOROSHI_CHALLENGE_FORCE_V1=true

# ---------------------------------------------------------------------------
# Consumer Info JWT (Otoroshi-Claims header processing)
# ---------------------------------------------------------------------------

# Set to any non-empty value to enable Consumer Info JWT processing
export OTOROSHI_CONSUMER_INFO_ENABLED=true

# Header containing the Consumer Info JWT (default: Otoroshi-Claims)
export OTOROSHI_CONSUMER_INFO_HEADER=Otoroshi-Consumer-Infos

# Header where the decoded JSON payload is written.
# Defaults to the same header as OTOROSHI_CONSUMER_INFO_HEADER (replaces the JWT).
export OTOROSHI_CONSUMER_INFO_OUT_HEADER=user-profile

# Algorithm for Consumer Info JWT verification
# (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384 — default: HS512)
export OTOROSHI_CONSUMER_INFO_ALG=HS512

# HMAC secret, public key PEM, private key PEM, or file path to any of those.
# For asymmetric algorithms, public key is extracted automatically from a private key.
export OTOROSHI_CONSUMER_INFO_SECRET="my-consumer-info-secret"

# Set to any non-empty value to treat OTOROSHI_CONSUMER_INFO_SECRET as base64-encoded
#export OTOROSHI_CONSUMER_INFO_SECRET_BASE64=true

# Public key PEM (or path) for asymmetric Consumer Info verification.
# Takes precedence over OTOROSHI_CONSUMER_INFO_SECRET for key material.
#export OTOROSHI_CONSUMER_INFO_PUBLIC_KEY=/path/to/consumer-info-public.pem

# Set to any non-empty value to allow requests through when the Consumer Info
# header is absent or the token is invalid (default: strict — returns 401)
#export OTOROSHI_CONSUMER_INFO_PERMISSIVE=true

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

BINARY=${BINARY:-./target/debug/otoroshictl}

if [ ! -f "$BINARY" ]; then
  echo "Binary not found at $BINARY — run 'cargo build' first."
  exit 1
fi

exec "$BINARY" challenge proxy
