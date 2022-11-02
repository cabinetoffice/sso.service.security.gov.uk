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

source build/source_python.sh
if [ -z "$PYTHON" ]; then
  echo "python not found!"
  exit 1
fi

rm ./*.zip || echo "No ZIPs to delete"
rm -rf .target || echo "No .target/ to delete"
mkdir .target

$PYTHON -m pip install -r requirements.txt -t .target/ --upgrade --no-user
$PYTHON -m pip install \
    --platform manylinux2010_x86_64 \
    --implementation cp \
    --python 3.9 \
    --only-binary=:all: --upgrade \
    --target .target/ \
    cryptography

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
