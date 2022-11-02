#!/usr/bin/env bash
set -euo pipefail

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

AWS_CLOUDFRONT_KEY_FILE=".cf-key"

if [[ "${AWS_CLOUDFRONT_KEY:+isset}" != "isset" ]]; then
  build/set_cfkey.sh

  AWS_CLOUDFRONT_KEY=""
  if [ -f "$AWS_CLOUDFRONT_KEY_FILE" ]; then
    TMPKEY="$(tr -d "[:space:]" < "$AWS_CLOUDFRONT_KEY_FILE")"
    if [ -n "$TMPKEY" ]; then
        AWS_CLOUDFRONT_KEY="$TMPKEY"
    fi
  fi
fi

echo "$AWS_CLOUDFRONT_KEY" > "$AWS_CLOUDFRONT_KEY_FILE"
export AWS_CLOUDFRONT_KEY="$AWS_CLOUDFRONT_KEY"

cd "$CWD"
