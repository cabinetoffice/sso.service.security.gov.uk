#!/usr/bin/env bash
# shellcheck disable=SC1091

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

source build/source_cfkey.sh
if [ -z "$AWS_CLOUDFRONT_KEY" ]; then
  echo ".cf-key not found!"
  exit 1
fi

cd terraform/viewer-request/

if [ ! -z "$(command -v nvm)" ]; then
  nvm install
  nvm use
fi

if [ -z "$(command -v npm)" ]; then
  echo "npm command not found!"
  exit 1
fi

npm install
npm test

cd "$CWD"
