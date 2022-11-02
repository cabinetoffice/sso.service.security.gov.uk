#!/usr/bin/env bash
set -euo pipefail

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

MAIN_AWS_CLOUDFRONT_KEY_FILE=".cf-key"

if [[ "${AWS_CLOUDFRONT_KEY:+isset}" != "isset" ]]; then
  if [[ "${TF_WORKSPACE:+isset}" != "isset" && -n "$(command -v terraform || echo '')" ]]; then
    TF_WORKSPACE=$(terraform -chdir=terraform workspace show | tr -d '[:space:]')
  fi
  if [ -n "$TF_WORKSPACE" ]; then
    CFKEYSOURCE="${MAIN_AWS_CLOUDFRONT_KEY_FILE}.${TF_WORKSPACE}"
    echo "Attempting to read from ${CFKEYSOURCE}..."
    if [ -f "$CFKEYSOURCE" ]; then
      AWS_CLOUDFRONT_KEY=$(tr -d "[:space:]" < "$CFKEYSOURCE")
    fi
  fi
fi

if [ -n "$AWS_CLOUDFRONT_KEY" ]; then
  echo "AWS_CLOUDFRONT_KEY has been set."
  echo "$AWS_CLOUDFRONT_KEY" > "$MAIN_AWS_CLOUDFRONT_KEY_FILE"
else
  echo "AWS_CLOUDFRONT_KEY not set..."
  exit 1
fi

cd "$CWD"
