#!/usr/bin/env bash

if [ ! -f .cf-key ]; then
    echo ".cf-key missing!"
    exit 1
fi

rm ./*.zip || echo "No ZIPs to delete"
rm -rf .target || echo "No .target/ to delete"
mkdir .target

python3.9 -m pip install -r requirements.txt -t .target/ --upgrade --no-user
python3.9 -m pip install \
    --platform manylinux2010_x86_64 \
    --implementation cp \
    --python 3.9 \
    --only-binary=:all: --upgrade \
    --target .target/ \
    cryptography

cp ./*.py .target/
cp .env.shared .target/

MAIN_CSS_HASH=($(md5sum assets/main.css))
MAIN_JS_HASH=($(md5sum assets/main.js))
echo "MAIN_CSS_HASH=${MAIN_CSS_HASH}" >> .target/.env.shared
echo "MAIN_JS_HASH=${MAIN_JS_HASH}" >> .target/.env.shared

echo "AWS_CLOUDFRONT_KEY=$(cat .cf-key)" >> .target/.env.shared

cp -r templates/ .target/
cp -r assets/ .target/

cd .target/ || exit 1

find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

zip -r ../target.zip .

cd ../
