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

cp ./*.py .target/
cp .env.shared .target/

./build/set_env-shared_lambda_build.sh

cp -r templates/ .target/
cp -r assets/ .target/

cd .target/ || exit 1

find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

ZIP_FILE="../target.zip"
zip -r "$ZIP_FILE" .
if [ ! -f "$ZIP_FILE" ]; then
  echo "ZIP not found!"
  exit 1
fi

cd "$CWD"
