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

source build/source_python.sh
if [[ "${PYTHON:+isset}" != "isset" ]]; then
  echo "python not found!"
  exit 1
fi

rm ./*.zip || echo "No ZIPs to delete"
rm -rf .target || echo "No .target/ to delete"
mkdir .target

CRLIB=$(grep cryptography requirements.txt | cut -d';' -f1)
grep -v cryptography requirements.txt > .install_requirements.txt

$PYTHON -m pip install -r .install_requirements.txt -t .target/ --upgrade --no-user
$PYTHON -m pip install \
    --upgrade \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --only-binary=:all: \
    --target .target/ \
    "$CRLIB"

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
sleep 1s
if [ ! -f "$ZIP_FILE" ]; then
  echo "ZIP not found!"
  exit 1
fi

cd "$CWD"
