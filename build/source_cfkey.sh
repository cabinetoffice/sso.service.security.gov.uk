#!/usr/bin/env bash

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

if [ -z "$AWS_CLOUDFRONT_KEY" ]; then
  build/set_cfkey.sh

  AWS_CLOUDFRONT_KEY=""
  AWS_CLOUDFRONT_KEY_FILE=".cf-key"
  if [ -f "$AWS_CLOUDFRONT_KEY_FILE" ]; then
    TMPKEY="$(tr -d "[:space:]" < "$AWS_CLOUDFRONT_KEY_FILE")"
    if [ ! -z "$TMPKEY" ]; then
        AWS_CLOUDFRONT_KEY="$TMPKEY"
    fi
  fi
fi

export AWS_CLOUDFRONT_KEY="$AWS_CLOUDFRONT_KEY"
cd "$CWD"
