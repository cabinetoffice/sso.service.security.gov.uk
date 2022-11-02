#!/usr/bin/env bash
# shellcheck disable=SC1091

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

cd terraform/viewer-response/

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
