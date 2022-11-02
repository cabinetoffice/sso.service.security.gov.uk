#!/usr/bin/env bash
# shellcheck disable=SC1091
set -euo pipefail

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

source build/source_cfkey.sh
if [[ "${AWS_CLOUDFRONT_KEY:+isset}" != "isset" ]]; then
  echo ".cf-key not found!"
  exit 1
fi

cd terraform/viewer-request/

if [ -n "$(command -v nvm || echo '')" ]; then
  nvm install
  nvm use
fi

if [ -z "$(command -v npm || echo '')" ]; then
  echo "npm command not found!"
  exit 1
fi

npm install
npm test

cd "$CWD"
