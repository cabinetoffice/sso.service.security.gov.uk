#!/usr/bin/env bash

CWD="$PWD"
if [[ $PWD = */build ]]; then
  cd ../
fi

PYTHONVERSIONFILE=".python-version"

if [ ! -f "$PYTHONVERSIONFILE" ]; then echo "$PYTHONVERSIONFILE missing!"; exit 1; fi
PYTHONREQUIRED=$(tr -d "[:space:]" < "$PYTHONVERSIONFILE")

MAJORPYTHONREQ=$(echo "$PYTHONREQUIRED" | cut -f1 -d '.')

PYTHON="$(command -v python)"
if [ -z "$PYTHON" ]; then
  PYTHON="$(command -v python"$PYTHONREQUIRED")"
fi
if [ -z "$PYTHON" ]; then
  PYTHON="$(command -v python"$MAJORPYTHONREQ")"
fi

export PYTHON="$PYTHON"
export PYTHONVERSION="$PYTHONREQUIRED"
cd "$CWD"
