import hashlib
import secrets
import time
import json
import re
import jwt_signing

from sso_factors import FactorQuality, calculate_auth_quality
from sso_data_access import read_file, write_file, delete_file, read_all_files
from sso_utils import jprint, env_var

SUB_EMAIL_SALT = env_var("SUB_EMAIL_SALT")

# ensure the S3 bucket lifecyle rules are updated with these
AUTH_CODE_TIMEOUT = int(env_var("AUTH_CODE_TIMEOUT"))
ACCESS_CODE_TIMEOUT = int(env_var("ACCESS_CODE_TIMEOUT"))

CURRENT_SIGNING_KID = env_var("CURRENT_SIGNING_KID")

IS_HTTPS = env_var("IS_HTTPS", "f", return_bool=True)
DOMAIN = env_var("DOMAIN")
URL_PREFIX = f"http{'s' if IS_HTTPS else ''}://{DOMAIN}"

ENVIRONMENT = env_var("ENVIRONMENT", "development")
IS_PROD = "production" == ENVIRONMENT.lower()

_individual_clients = {}


def get_clients() -> dict:
    res = {}

    from_files = read_all_files(bucket_type="clients")
    for fc in from_files:
        if fc and fc.startswith("{"):
            res.update(json.loads(fc))

    from_env = env_var("OAUTH_CLIENTS_JSON_OBJECT")
    if from_env and from_env.startswith("{"):
        res.update(json.loads(from_env))

    if not IS_PROD:
        jprint({"function": "get_clients", "clients": res})

    for c in res:
        if "client_id" not in res[c]:
            res[c]["client_id"] = c

    return res


def get_client(client_id: str) -> dict:
    if client_id:
        if client_id not in _individual_clients:
            clients = get_clients()
            if client_id in clients:
                _individual_clients[client_id] = clients[client_id]
                _individual_clients[client_id]["ok"] = True
                if "client_id" not in _individual_clients[client_id]:
                    _individual_clients[client_id]["client_id"] = client_id

        if client_id in _individual_clients:
            return _individual_clients[client_id]

    return {"ok": False}


def is_client(client_id: str) -> bool:
    client = get_client(client_id)
    return "ok" in client and client["ok"] == True


def generate_google_auth_url(sub: str) -> str:
    res = None


def get_user_by_auth_code(client_id: str, client_secret: str, auth_code: str) -> dict:
    res = {}

    clients = get_clients()

    if client_id in clients and client_secret == clients[client_id]["secret"]:
        try:
            ac = read_file(f"auth_codes/{auth_code}.json", "{}")
            if ac:
                jac = json.loads(ac)
                if "sub" in jac and "write_time" in jac:
                    gus = get_user_sub(sub=jac["sub"])
                    if (
                        gus
                        and "auth_codes" in gus
                        and auth_code in gus["auth_codes"]
                        and jac["write_time"] >= (time.time() - AUTH_CODE_TIMEOUT)
                    ):
                        res = gus
                        res["scopes"] = jac["scopes"] if "scopes" in jac else ["openid"]
                        res["pf_quality"] = (
                            jac["pf_quality"] if "pf_quality" in jac else None
                        )
                        res["mfa_quality"] = (
                            jac["mfa_quality"] if "mfa_quality" in jac else None
                        )
        except Exception as e:
            jprint("get_user_by_auth_code:", e)

        delete_auth_code(auth_code)

    return res


def delete_auth_code(auth_code: str) -> bool:
    res = False

    try:
        ac = read_file(f"auth_codes/{auth_code}.json", "{}")
        jac = json.loads(ac)
        if "sub" in jac:
            gus = get_user_sub(sub=jac["sub"])
            if gus and "auth_codes" in gus and auth_code in gus["auth_codes"]:
                acs = gus["auth_codes"]
                acs.remove(auth_code)
                res = update_subs_json(jac["sub"], {"auth_codes": acs})
    except Exception as e:
        jprint("delete_auth_code:1:", e)

    try:
        delete_file(f"auth_codes/{auth_code}.json")
    except Exception as e:
        jprint("delete_auth_code:2:", e)

    return res


def get_available_scopes() -> list:
    return [
        "openid",
        "email",
        "profile",
        "user_attribute:global:read",
        "user_attribute:global:write",
    ]


def generate_id_token(
    client_id: str,
    user: dict,
    scopes: list = ["openid"],
    pf_quality: FactorQuality = FactorQuality.none,
    mfa_quality: FactorQuality = FactorQuality.none,
    time_now: int = int(time.time()),
):
    id_token = None

    expiry = 3600
    exp_time = time_now + expiry

    sub = user["sub"]
    email = user["email"]

    pfq = FactorQuality.get(pf_quality)
    mfq = FactorQuality.get(mfa_quality)
    aq = calculate_auth_quality(pfq, mfq)

    payload = {
        "iss": URL_PREFIX,
        "iat": time_now,
        "exp": exp_time,
        "aud": client_id,
        "sub": sub,
        "pf_quality": pfq.name,
        "mfa_quality": mfq.name,
        "auth_quality": aq.name,
    }

    # mfa quality: none, low, medium, high
    # https://www.gov.uk/government/publications/authentication-credentials-for-online-government-services/giving-users-access-to-online-services

    if "email" in scopes:
        payload["email"] = email
        payload["email_verified"] = True

    if "nonce" in user:
        payload["nonce"] = user["nonce"]

    if "profile" in scopes:
        dn = None
        if "attributes" in user and "display_name" in user["attributes"]:
            dn = user["attributes"]["display_name"]
        payload["display_name"] = dn
        payload["nickname"] = dn

    id_token = jwt_signing.sign(payload, kid=CURRENT_SIGNING_KID)

    return id_token


def sanitise_scopes(raw_scope=None) -> list:
    scopes = []
    if not raw_scope:
        return scopes

    if type(raw_scope) == list:
        raw_scope = " ".join(raw_scope)

    raw_scope = str(raw_scope).lower().replace("%20", " ")
    raw_scope = re.sub(r"[\'\"\[\]\,]", " ", raw_scope)
    raw_scope = re.sub(r"\s+", " ", raw_scope).strip()

    raw_scopes = raw_scope.split(" ")
    for s in get_available_scopes():
        if s in raw_scopes:
            scopes.append(s)

    return scopes


def create_auth_code(
    client_id: str,
    sub: str,
    scopes: list = [],
    pf_quality: str = None,
    mfa_quality: str = None,
) -> str:
    gus = get_user_sub(sub=sub)
    clients = get_clients()
    if client_id in clients and "email" in gus:
        try:
            auth_code = secrets.token_hex(nbytes=32)

            # have at most 3 concurrent auth codes, two existing plus new one
            auth_codes = gus["auth_codes"][-2:] if "auth_codes" in gus else []
            auth_codes.append(auth_code)
            update_subs_json(sub, {"auth_codes": auth_codes})

            write_file(
                f"auth_codes/{auth_code}.json",
                json.dumps(
                    {
                        "sub": sub,
                        "write_time": time.time(),
                        "scopes": scopes,
                        "pf_quality": pf_quality,
                        "mfa_quality": mfa_quality,
                    }
                ),
            )
            return auth_code
        except Exception as e:
            jprint({"error", e})

    return None


def get_user_by_access_code(access_code: str) -> dict:
    res = {}

    try:
        ac = read_file(f"access_codes/{access_code}.json", "{}")
        if ac:
            jac = json.loads(ac)
            if "sub" in jac and "write_time" in jac:
                gus = get_user_sub(sub=jac["sub"])
                if (
                    gus
                    and "access_codes" in gus
                    and access_code in gus["access_codes"]
                    and jac["write_time"] >= (time.time() - ACCESS_CODE_TIMEOUT)
                ):
                    res = gus
                    res["scopes"] = jac["scopes"] if "scopes" in jac else ["openid"]
                    res["pf_quality"] = (
                        jac["pf_quality"] if "pf_quality" in jac else None
                    )
                    res["mfa_quality"] = (
                        jac["mfa_quality"] if "mfa_quality" in jac else None
                    )
    except Exception as e:
        jprint("get_user_by_access_code:", e)

    # delete_access_code(access_code)

    return res


def delete_access_code(access_code: str) -> bool:
    res = False

    try:
        ac = read_file(f"access_codes/{access_code}.json", "{}")
        jac = json.loads(ac)
        if "sub" in jac:
            gus = get_user_sub(sub=jac["sub"])
            if gus and "access_codes" in gus and access_code in gus["access_codes"]:
                acs = gus["access_codes"]
                acs.remove(access_code)
                res = update_subs_json(jac["sub"], {"access_codes": acs})
    except Exception as e:
        jprint("delete_access_code:1:", e)

    try:
        delete_file(f"access_codes/{access_code}.json")
    except Exception as e:
        jprint("delete_access_code:2:", e)

    return res


def create_access_code(
    sub: str, scopes: list = [], pf_quality: str = None, mfa_quality: str = None
) -> str:
    gus = get_user_sub(sub=sub)
    if "email" in gus:
        try:
            access_code = secrets.token_hex(nbytes=32)

            # have at most 3 access codes, 2 existing and 1 new
            access_codes = gus["access_codes"][-2:] if "access_codes" in gus else []
            access_codes.append(access_code)

            update_subs_json(sub, {"access_codes": access_codes})

            write_file(
                f"access_codes/{access_code}.json",
                json.dumps(
                    {
                        "sub": sub,
                        "write_time": time.time(),
                        "scopes": scopes,
                        "pf_quality": pf_quality,
                        "mfa_quality": mfa_quality,
                    }
                ),
            )

            return access_code
        except Exception as e:
            jprint({"error": e})
    return None


def get_email_sub_hash(email: str) -> str:
    h = hashlib.new("sha256")
    h.update(email.encode("utf-8"))
    h.update(SUB_EMAIL_SALT.encode("utf-8"))
    ehex = h.hexdigest()
    return ehex


def check_user_sub(sub: str) -> bool:
    return "email" in get_user_sub(sub=sub)


def get_user_sub(
    google_sub: str = None,
    microsoft_sub: str = None,
    email: str = None,
    sub: str = None,
) -> dict:
    if sub is None:
        if google_sub:
            gs = read_file(f"subs/gmail/{google_sub}")
            if gs is not None:
                sub = gs.strip()

        if microsoft_sub:
            ms = read_file(f"subs/microsoft/{microsoft_sub}")
            if ms is not None:
                sub = ms.strip()

        if email:
            es = read_file(f"subs/email/{get_email_sub_hash(email)}")
            if es is not None:
                sub = es.strip()

    if sub and len(sub) == 64:
        ss = read_file(f"subs/sub/{sub}.json")
        if ss is not None:
            try:
                jss = json.loads(ss)
                return jss
            except Exception as e:
                jprint("get_user_sub: sub:", e)

    return {}


def write_user_sub(
    google_sub: str = None,
    microsoft_sub: str = None,
    email: str = None,
    sub: str = None,
) -> str:
    if not google_sub and not microsoft_sub and not email:
        return None

    usub = {}

    gus = get_user_sub(google_sub, microsoft_sub, email)
    if not gus:
        sub = secrets.token_hex(nbytes=32)
        jprint("write_user_sub: new sub:", sub)
    else:
        sub = gus["sub"]
        usub_temp = read_file(f"subs/sub/{sub}.json")
        if usub_temp:
            try:
                usub = json.loads(usub_temp)
                jprint("write_user_sub: using existing sub:", sub)
            except Exception as e:
                jprint({"error": e})

    if google_sub:
        write_file(f"subs/gmail/{google_sub}", sub)
        usub.update({"google_sub": google_sub})

    if microsoft_sub:
        write_file(f"subs/microsoft/{microsoft_sub}", sub)
        usub.update({"microsoft_sub": microsoft_sub})

    if email:
        email_hash = get_email_sub_hash(email)
        write_file(f"subs/email/{email_hash}", sub)
        usub.update({"email": email, "email_hash": email_hash})

    jprint("write_user_sub: updating sub:", sub)
    usub.update({"sub": sub})
    update_subs_json(sub, usub)

    return sub


def update_subs_attributes(sub: str, attribute_updates: dict = {}) -> bool:
    res = False

    try:
        gus = get_user_sub(sub=sub)
        if "attributes" not in gus:
            gus["attributes"] = {}
        gus["attributes"].update(attribute_updates)
        res = update_subs_json(sub, {"attributes": gus["attributes"]})
    except Exception as e:
        jprint("update_subs_attributes:", e)

    return res


def get_subs_attributes(
    sub: str = None,
    email: str = None,
    all_attributes: bool = False,
    attributes: list = [],
    set_attribute_none: bool = False,
) -> dict:
    res = {}
    usub = get_user_sub(email=email, sub=sub)
    if usub and "attributes" in usub:
        if all_attributes:
            return usub["attributes"]
    else:
        usub = {"attributes": {}}

    for a in attributes:
        if a in usub["attributes"]:
            res[a] = usub["attributes"][a]
        elif set_attribute_none:
            res[a] = None
    return res


def update_subs_json(sub: str, updates: dict) -> bool:
    usub = {"sub": sub, "attributes": {}}

    try:

        usub_temp = read_file(f"subs/sub/{sub}.json")
        if usub_temp:
            usub = json.loads(usub_temp)

        usub.update(updates)
        usub.update({"last_write": time.time()})
        write_file(
            f"subs/sub/{sub}.json",
            json.dumps(usub),
        )
        return True

    except Exception as e:
        jprint("update_subs_json:", e)

    return False
