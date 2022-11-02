#!/usr/bin/env bash

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

MAIN_AWS_CLOUDFRONT_KEY_FILE=".cf-key"

if [ -z "$AWS_CLOUDFRONT_KEY" ]; then
  if [[ -z "$TF_WORKSPACE" && ! -z "$(command -v terraform)" ]]; then
    TF_WORKSPACE=$(terraform -chdir=terraform workspace show | tr -d '[:space:]')
  fi
  if [ ! -z "$TF_WORKSPACE" ]; then
    CFKEYSOURCE="${MAIN_AWS_CLOUDFRONT_KEY_FILE}.${TF_WORKSPACE}"
    echo "Attempting to read from ${CFKEYSOURCE}"
    if [ -f "$CFKEYSOURCE" ]; then
      AWS_CLOUDFRONT_KEY=$(tr -d "[:space:]" < "$CFKEYSOURCE")
    fi
  fi
fi

if [ ! -z "$AWS_CLOUDFRONT_KEY" ]; then
  echo "$AWS_CLOUDFRONT_KEY" > "$MAIN_AWS_CLOUDFRONT_KEY_FILE"
else
  echo "AWS_CLOUDFRONT_KEY not set..."
  exit 1
fi

cd "$CWD"
