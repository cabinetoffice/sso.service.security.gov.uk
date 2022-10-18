#!/usr/bin/env pwsh

$env:ENVIRONMENT="development"
$env:FLASK_ENV="development"
python -m flask run --host 0.0.0.0 --port 5001
