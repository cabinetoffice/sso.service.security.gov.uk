#!/usr/bin/env bash
set -euo pipefail

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

echo "Setting the .target/.env.shared environment variables..."

MAIN_CSS_HASH=$(md5sum assets/main.css | cut -d ' ' -f1)
MAIN_JS_HASH=$(md5sum assets/main.js | cut -d ' ' -f1)
{
  echo "MAIN_CSS_HASH=${MAIN_CSS_HASH}"
  echo "MAIN_JS_HASH=${MAIN_JS_HASH}"
  echo "AWS_CLOUDFRONT_KEY=$(cat .cf-key)"
} >> .target/.env.shared

cd "$CWD"
