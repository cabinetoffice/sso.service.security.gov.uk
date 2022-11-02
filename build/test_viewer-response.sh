#!/usr/bin/env bash
# shellcheck disable=SC1091
set -euo pipefail

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

cd terraform/viewer-response/

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
