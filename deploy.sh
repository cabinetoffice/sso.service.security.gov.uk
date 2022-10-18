#!/usr/bin/env bash

./build.sh

aws s3 sync ./assets/ s3://sso.nonprod-service.security.gov.uk/assets/
aws s3 sync ./assets/ s3://sso.service.security.gov.uk/assets/

cd terraform/ || exit 1

cd viewer-request/ || exit 1
npm install
npm test

cd ../viewer-response/ || exit 1
npm install
npm test

cd ../ || exit 1

terraform init
terraform apply
