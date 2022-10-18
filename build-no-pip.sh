#!/usr/bin/env bash

cp ./*.py .target/
cp .env.* .target/

# MAIN_CSS_HASH=($(md5sum assets/main.css))
# echo "MAIN_CSS_HASH=${MAIN_CSS_HASH}" >> .target/.env.shared

cp -r templates/ .target/
cp -r assets/ .target/

cd .target/ || exit 1

find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

zip -r ../target.zip .

cd ../
