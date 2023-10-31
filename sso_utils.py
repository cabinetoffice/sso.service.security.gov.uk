import os
import random
import secrets
import string
import re
import json

from datetime import datetime
from dotenv import dotenv_values
from base64 import b64decode

file_variables = {**dotenv_values(".env.shared")}  # all environments variables

redact_replacement = "REDACTED"
redact_strings = []
redact_prefixes = []


def set_redacted(strings: list = [], prefixes: list = []):
    global redact_strings
    global redact_prefixes

    for s in strings:
        if s and s not in redact_strings:
            redact_strings.append(s)

    for p in prefixes:
        if p and p not in redact_prefixes:
            redact_prefixes.append(p)


def env_var(env: str, default: str = None, return_bool: bool = False):
    res = default
    if env:
        if env in os.environ:
            res = os.environ[env]
        elif env in file_variables:
            res = file_variables[env]

    if return_bool:
        res = True if res.lower().startswith("t") or res == "1" else False

    return res


ENVIRONMENT = env_var("ENVIRONMENT", "development")
IS_PROD = ENVIRONMENT.lower().startswith("prod")
if ENVIRONMENT == "development":
    file_variables.update(dotenv_values(".env.secrets.test"))


def to_list(s: str, delimiter: str = ",", to_lower: bool = True) -> list:
    res = []

    if s:
        res = [t.strip().lower() if to_lower else t.strip() for t in s.split(delimiter)]

    return res


def decrypt_env_var(env: str) -> str:
    DECRYPTED = ""

    try:
        import boto3

        DECRYPTED = (
            boto3.client("kms")
            .decrypt(
                CiphertextBlob=b64decode(env_var(env)),
                EncryptionContext={
                    "LambdaFunctionName": env_var("AWS_LAMBDA_FUNCTION_NAME")
                },
            )["Plaintext"]
            .decode("utf-8")
        )
    except Exception as e:
        print("decrypt_env_var failed")

    return DECRYPTED


def sanitise_string(
    s: str,
    allow_numbers: bool = True,
    allow_letters: bool = True,
    allow_lower: bool = True,
    allow_upper: bool = True,
    allow_space: bool = True,
    allow_accented_chars: bool = True,
    allow_single_quotes: bool = True,
    allow_hyphen: bool = True,
    allow_underscore: bool = False,
    allow_at_symbol: bool = False,
    additional_allowed_chars: list = [],
    normalise_single_quotes: bool = True,
    perform_lower: bool = False,
    perform_upper: bool = False,
    perform_title: bool = False,
    reverse: bool = False,
    max_length: int = 200,
) -> str:
    regex_string = "[^"
    regex_string += "a-z" if allow_letters and allow_lower else ""
    regex_string += "A-Z" if allow_letters and allow_upper else ""
    regex_string += "0-9" if allow_numbers else ""
    regex_string += "A-ZÀ-ÖØ-öø-ÿ" if allow_letters and allow_accented_chars else ""
    regex_string += "'’′`" if allow_single_quotes else ""
    regex_string += " " if allow_space else ""
    regex_string += "\\-" if allow_hyphen else ""
    regex_string += "_" if allow_underscore else ""
    regex_string += "@" if allow_at_symbol else ""
    regex_string += "".join(additional_allowed_chars)
    regex_string += "]"

    full_pattern = re.compile(regex_string)
    s = re.sub(full_pattern, "", s)

    if normalise_single_quotes:
        s = re.sub(r"[’′`]", "'", s)

    if perform_lower:
        s = s.lower()

    if perform_upper:
        s = s.upper()

    if perform_title:
        s = s.title()

    if reverse:
        s = s[::-1]

    return s[:max_length]


def random_string(
    length: int = 32, lower: bool = False, only_numbers: bool = False
) -> str:
    chars = "23456789"
    if not only_numbers:
        chars += "ABCEFGHJKMNPQRSTVXYZacdefghkmnpqrstvxyz"

    res = "".join(secrets.choice(chars) for _ in range(length))
    if lower:
        res = res.lower()
    return res


def redact_string(res):
    if not res:
        return ""

    regex_finds = []
    for p in redact_prefixes:
        if p:
            repr = re.compile(f"[\"'&\?\=]{p}[\"']?[:=]\s*[\"']?([\.a-zA-Z\-0-9\_\/]+)")
            for rf in repr.findall(res):
                if rf and len(rf) >= 10:
                    regex_finds.append(rf)

    to_redact = redact_strings + regex_finds

    for s in to_redact:
        if s in res:
            res = res.replace(s, redact_replacement)

    return res


def jprint(d=None, *argv):
    try:
        if type(d) != dict:
            d = {"message": str(d)}
        if argv:
            if "message" not in d:
                d["message"] = ""
            for a in argv:
                if type(a) == dict:
                    d.update(a)
                else:
                    d["message"] += " " + str(a)
            d["message"] = d["message"].strip()
    except:
        d = {}

    now = datetime.now()
    d = {"_datetime": now.strftime("%Y-%m-%dT%H:%M:%S.%f"), **d}

    res = redact_string(json.dumps(d, default=str))
    print(res)
    return res
