import json
import base64
import time
import hashlib
import boto3
import botocore
import traceback
import re
import os
import html
import jwt_signing
import sso_oidc
import werkzeug

from datetime import timedelta
from flask import (
    Flask,
    jsonify,
    send_from_directory,
    render_template,
    request,
    session,
    redirect,
    make_response,
)
from apig_wsgi import make_lambda_handler
from notifications_python_client.notifications import NotificationsAPIClient
from urllib.parse import parse_qs, unquote
from functools import wraps

from jinja_helper import renderTemplate
from sso_data_access import read_file, write_file
from sso_utils import random_string, env_var, sanitise_string, jprint, set_redacted
from sso_email_check import valid_email
from email_helper import email_parts
from sso_ua import guess_browser
from sso_google_auth import GoogleAuth
from sso_microsoft_auth import MicrosoftAuth
from sso_factors import FactorQuality, calculate_auth_quality
from sso_signedin import (
    get_csrf_session,
    CheckCSRFSession,
    UserShouldBeSignedIn,
)

ENVIRONMENT = env_var("ENVIRONMENT", "development")
jprint("Starting wsgi.py - ENVIRONMENT:", ENVIRONMENT)

AWS_CLOUDFRONT_KEY = env_var("AWS_CLOUDFRONT_KEY")

IS_PROD = ENVIRONMENT.lower().startswith("prod")
DEBUG = not IS_PROD
IS_ADMIN = env_var("IS_ADMIN", "f", return_bool=True)
IS_HTTPS = env_var("IS_HTTPS", "f", return_bool=True)

COOKIE_PREFIX = "__Host-" if IS_HTTPS else ""
COOKIE_NAME_SESSION = f"{COOKIE_PREFIX}Session-SSO"
COOKIE_NAME_BROWSER = f"{COOKIE_PREFIX}Browser-SSO"
COOKIE_NAME_REMEMBERME = f"{COOKIE_PREFIX}RememberMe-SSO"

COOKIE_BROWSER_LENGTH = 64
CURRENT_SIGNING_KID = env_var("CURRENT_SIGNING_KID")
DOMAIN = env_var("DOMAIN")
URL_PREFIX = f"http{'s' if IS_HTTPS or IS_PROD else ''}://{DOMAIN}"

USE_NOTIFY = env_var("USE_NOTIFY", "f", return_bool=True)
NOTIFY_API_KEY = env_var("NOTIFY_API_KEY")
notifications_client = (
    NotificationsAPIClient(NOTIFY_API_KEY) if USE_NOTIFY and NOTIFY_API_KEY else None
)

GOOGLE_CLIENT_ID = env_var("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = env_var("GOOGLE_CLIENT_SECRET")
ga = None
try:
    ga = GoogleAuth(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    jprint({"GoogleAuth": {"in_use": True}})
except Exception as e:
    jprint({"GoogleAuth": {"error": e, "in_use": False}})

MICROSOFT_CLIENT_ID = env_var("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = env_var("MICROSOFT_CLIENT_SECRET")
ma = None
try:
    ma = MicrosoftAuth(MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET)
    jprint({"MicrosoftAuth": {"in_use": True}})
except Exception as e:
    jprint({"MicrosoftAuth": {"error": e, "in_use": False}})

FLASK_SECRET_KEY = env_var("FLASK_SECRET_KEY")
app = Flask(__name__)

if IS_PROD:
    set_redacted(
        strings=[
            NOTIFY_API_KEY,
            FLASK_SECRET_KEY,
            GOOGLE_CLIENT_SECRET,
            MICROSOFT_CLIENT_ID,
            MICROSOFT_CLIENT_SECRET,
        ],
        prefixes=[
            "client_secret",
            "code",
            "id_token",
            "token",
            "secret",
            "x-cloudfront",
            COOKIE_NAME_SESSION,
            COOKIE_NAME_REMEMBERME,
        ],
    )
else:
    set_redacted(strings=[NOTIFY_API_KEY])
    app.config["TESTING"] = True
    app.config["DEBUG"] = True
    app.testing = True

app.config.update(
    ENV=ENVIRONMENT,
    SESSION_COOKIE_NAME=COOKIE_NAME_SESSION,
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_HTTPS,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SECRET_KEY=FLASK_SECRET_KEY,
    MAX_CONTENT_LENGTH=120 * 1024 * 1024,
)

assets = werkzeug.utils.safe_join(os.path.dirname(__file__), "assets")
alb_lambda_handler = make_lambda_handler(app)


def client_ip():
    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        return request.environ["REMOTE_ADDR"]
    else:
        return request.environ["HTTP_X_FORWARDED_FOR"]


def client_country():
    return request.headers.get("cloudfront-viewer-country-name", "Unknown")


def search_request_values(res: dict, search: dict, find: str):
    k, v = (None, None)
    d = dict(search) if search else {}
    for key in d:
        nkey = key.lower().strip()
        if nkey and nkey == find.lower().strip():
            val = d[key]
            if type(val) == list:
                k, v = (find, val)
            else:
                k, v = (find, [val])
            break
    if k:
        if k not in res:
            res[k] = []
        for inh in v:
            if inh not in res[k]:
                res[k].append(inh)
    return res


def get_browser_cookie_value():
    raw_value = request.cookies.get(COOKIE_NAME_BROWSER, "").strip('"').strip()
    if raw_value and len(raw_value) == COOKIE_BROWSER_LENGTH:
        return raw_value
    return None


def SetBrowserCookie(f):
    @wraps(f)
    def wrap(*args, **kwds):
        response = f(*args, **kwds)
        if response:
            current = get_browser_cookie_value()
            if not current:
                response.set_cookie(
                    COOKIE_NAME_BROWSER,
                    random_string(length=COOKIE_BROWSER_LENGTH),
                    secure=IS_HTTPS,
                    httponly=True,
                    samesite="Lax",
                    max_age=31536000,
                )
        return response

    return wrap


def get_request_val(
    *keys: str,
    use_headers: bool = False,
    use_posted_data: bool = False,
    use_querystrings: bool = False,
    use_session: bool = False,
):
    grvs = get_request_vals(
        *keys,
        use_headers=use_headers,
        use_posted_data=use_posted_data,
        use_querystrings=use_querystrings,
        use_session=use_session,
        return_first=True,
    )

    if grvs and len(grvs) == 1:
        res = grvs[list(grvs.keys())[0]]
        if res:
            if type(res) == list and len(res) == 1:
                return res[0]
            elif type(res) == list:
                return ",".join([str(s) for s in res])
            else:
                return str(res)
    return None


def get_request_vals(
    *keys: str,
    use_headers: bool = False,
    use_posted_data: bool = False,
    use_querystrings: bool = False,
    use_session: bool = False,
    return_first: bool = False,
):
    res = {}
    if not keys:
        return res

    for key in keys:
        if use_headers:
            res = search_request_values(res, request.headers, key)
            if return_first and key in res:
                return {key: res[key]}
        if use_posted_data:
            res = search_request_values(res, request.form, key)
            if return_first and key in res:
                return {key: res[key]}
        if use_querystrings:
            res = search_request_values(res, request.args, key)
            if return_first and key in res:
                return {key: res[key]}
        if use_session:
            res = search_request_values(res, session, key)
            if return_first and key in res:
                return {key: res[key]}

    if DEBUG:
        jprint(
            {
                "get_request_vals: res": res,
                "keys": keys,
                "use_headers": use_headers,
                "use_posted_data": use_posted_data,
                "use_querystrings": use_querystrings,
                "use_session": use_session,
                "return_first": return_first,
                "session_dict": dict(session),
            }
        )

    return {
        k: (res[k][0] if len(res[k]) == 1 else res[k])
        if type(res[k]) == list
        else res[k]
        for k in res
    }


def lambda_handler(event, context):
    try:
        if AWS_CLOUDFRONT_KEY and "headers" in event:
            if (
                "via" in event["headers"]
                and "cloudfront" in event["headers"]["via"].lower()
            ):
                if "x-cloudfront" not in event["headers"]:
                    raise Exception("Missing x-cloudfront header")
                if event["headers"]["x-cloudfront"] != AWS_CLOUDFRONT_KEY:
                    raise Exception("x-cloudfront conflict")

        response = alb_lambda_handler(event, context)
        if "cache-control" not in response["headers"]:
            response["headers"][
                "cache-control"
            ] = "private, no-cache, no-store, max-age=0"
            response["headers"]["pragma"] = "no-cache"

        print_obj = {
            "Request": event,
            "Response": {
                "statusCode": response["statusCode"],
                "headers": response["headers"],
                "body_length": len(response["body"]),
            },
        }
        if DEBUG:
            print_obj["body"] = base64.b64encode(response["body"].encode("utf-8"))
        jprint(print_obj)

        return response
    except Exception as e:
        jprint({"Request": event, "Response": None, "Error": traceback.format_exc()})
        return {"statusCode": 500}


@app.route("/internal/health")
def health_check():
    return "IMOK"


@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify(jwt_signing.get_jwks())


@app.route("/.well-known/openid-configuration")
def oidc_config():
    discovery = {
        "issuer": URL_PREFIX,
        "authorization_endpoint": f"{URL_PREFIX}/auth/oidc",
        "token_endpoint": f"{URL_PREFIX}/auth/token",
        "userinfo_endpoint": f"{URL_PREFIX}/auth/profile",
        "jwks_uri": f"{URL_PREFIX}/.well-known/jwks.json",
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
            # "none",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": sso_oidc.get_available_scopes(),
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            # "client_secret_jwt",
            # "none"
        ],
        "acr_values_supported": [
            "AAL1",
            "AAL2",
            "AAL3",
        ],
        "claims_supported": [
            "aud",
            "email",
            "exp",
            "iat",
            "iss",
            "sub",
            "display_name",
            "nickname",
            "auth_quality",
            "pf_quality",
            "mfa_quality",
            "acr",
            # "amr",
        ],
        "code_challenge_methods_supported": ["plain"],
        "grant_types_supported": ["implicit", "authorization_code"],
    }
    return jsonify(discovery)


@app.route("/auth/token", methods=["GET", "POST"])
def auth_token():
    keys = ["client_id", "client_secret", "code", "authorization", "token"]
    params = get_request_vals(
        *keys, use_querystrings=True, use_posted_data=True, use_headers=True
    )
    client_id = None
    gubac = {}

    if "authorization" in params and "Basic " in params["authorization"]:
        b64 = params["authorization"].split(" ")[1]
        if b64:
            athz = base64.b64decode(b64).decode("utf-8")
            if athz and ":" in athz:
                client_creds = athz.split(":", 1)
                params["client_id"] = client_creds[0]
                params["client_secret"] = client_creds[1]

    if "code" in params:
        for k in ["client_id", "client_secret"]:
            value = params.get(k)
            if not value:
                jprint(
                    {
                        "path": "/auth/token",
                        "method": request.method,
                        "error": f"auth_token: key '{k}' does not exist, returning 400",
                    }
                )
                return jsonify({"error": "invalid_client"}), 400
            elif len(value) != 64 and len(value) != 36:
                jprint(
                    {
                        "path": "/auth/token",
                        "method": request.method,
                        "error": f"auth_token: key '{k}' invalid, returning 400",
                    }
                )
                return jsonify({"error": "unauthorized_client"}), 400

        client_id = params["client_id"]
        client_secret = params["client_secret"]
        auth_code = params["code"]
        gubac = sso_oidc.get_user_by_auth_code(client_id, client_secret, auth_code)
        if not gubac or "sub" not in gubac:
            jprint(
                {
                    "path": "/auth/token",
                    "method": request.method,
                    "error": "auth_token: auth_code invalid, returning 400",
                }
            )
            return jsonify({"error": "invalid_code"}), 400

    if "token" in params:
        access_code = params["token"]
        gubac = sso_oidc.get_user_by_access_code(access_code)
        if not gubac or "sub" not in gubac:
            jprint(
                {
                    "path": "/auth/token",
                    "method": request.method,
                    "error": "auth_token: access_code invalid, returning 400",
                }
            )
            return jsonify({"error": "invalid_token"}), 400
        elif "client_id" in gubac and gubac["client_id"]:
            if "client_id" in params and params["client_id"] != gubac["client_id"]:
                return jsonify({"error": "invalid_request"}), 400
            client_id = gubac["client_id"]

    if not gubac or "sub" not in gubac:
        return jsonify({"error": "invalid_parameters"}), 400

    scopes = gubac["scopes"]

    time_now = int(time.time())
    id_token = sso_oidc.generate_id_token(
        client_id=client_id,
        user=gubac,
        scopes=scopes,
        pf_quality=gubac["pf_quality"],
        mfa_quality=gubac["mfa_quality"],
        time_now=time_now,
    )
    if id_token is None or not id_token:
        jprint(
            {
                "path": "/auth/token",
                "method": request.method,
                "error": "auth_token: id_token invalid, returning 400",
            }
        )
        return jsonify({"error": "invalid_grant"}), 400

    access_token = sso_oidc.create_access_code(
        gubac["sub"],
        scopes,
        gubac["pf_quality"],
        gubac["mfa_quality"],
        client_id=client_id,
    )
    if access_token is None or not access_token:
        jprint(
            {
                "path": "/auth/token",
                "method": request.method,
                "error": "auth_token: access_token invalid, returning 400",
            }
        )
        return jsonify({"error": "invalid_grant"}), 400

    token = {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 7200,
        "scope": " ".join(scopes),
    }
    resp_body = json.dumps(token, indent=2, default=str)

    if DEBUG:
        jprint(
            {"path": "/auth/token", "method": request.method, "resp_body": resp_body}
        )

    return make_response(resp_body, 200, {"Content-Type": "application/json"})


@app.route("/auth/profile", methods=["GET", "POST"])
def auth_profile():
    user_info = {
        "sub": None,
        "pf_quality": FactorQuality.none,
        "mfa_quality": FactorQuality.none,
        "auth_quality": FactorQuality.none,
        "acr": None,
        # "amr": "",
    }

    authorization = None
    id_token = None

    authorization = get_request_val(
        "Authorization",
        "Authorisation",
        "Token",
        use_headers=True,
        use_querystrings=True,
        use_posted_data=True,
    )

    id_token = get_request_val(
        "id_token",
        use_headers=True,
        use_querystrings=True,
        use_posted_data=True,
    )

    jprint(
        {
            "path": "/auth/profile",
            "method": request.method,
            "authorization": authorization,
            "id_token": id_token,
        }
    )

    if authorization:
        if authorization.lower().startswith("bearer "):
            authorization = authorization.split(" ", 1)[1].strip()
        if not re.search(r"^[a-zA-Z0-9]{64}$", authorization):
            authorization = None
            user_info["error"] = "Bad or no access_token sent"
            jprint(
                {
                    "path": "/auth/profile",
                    "method": request.method,
                    "error": 400,
                    "user_info": user_info,
                }
            )
            return make_response(jsonify(user_info), 400)

    gus = {}

    if authorization:
        gus = sso_oidc.get_user_by_access_code(authorization)

    if session and "sub" in session:
        gus = sso_oidc.get_user_sub(sub=session["sub"])
        gus["scopes"] = []
        gus["pf_quality"] = session["pf_quality"]
        gus["mfa_quality"] = session["mfa_quality"]

    if gus and "sub" in gus:
        user_info["sub"] = gus["sub"]

        if "pf_quality" in gus:
            user_info["pf_quality"] = FactorQuality.get(gus["pf_quality"])

        if "mfa_quality" in gus:
            user_info["mfa_quality"] = FactorQuality.get(gus["mfa_quality"])

        user_info["auth_quality"] = calculate_auth_quality(
            user_info["pf_quality"], user_info["mfa_quality"]
        )

        user_info["acr"] = FactorQuality.get(user_info["auth_quality"]).acr()

        if "email" in gus["scopes"] and "email" in gus:
            user_info["email"] = gus["email"]
            user_info["email_verified"] = True

        if "profile" in gus["scopes"]:
            dn = None
            if "attributes" in gus and "display_name" in gus["attributes"]:
                dn = gus["attributes"]["display_name"]
            user_info["display_name"] = dn
            user_info["nickname"] = dn

    jprint({"path": "/auth/profile", "method": request.method, "user_info": user_info})

    return jsonify(user_info)


@app.route("/auth/microsoft_callback", methods=["GET", "POST"])
@SetBrowserCookie
def microsoft_callback():
    redirect_url = "/dashboard"
    browser_cookie_value = get_browser_cookie_value()

    if not ma:
        return returnError(501, "Not implemented")

    if "microsoft_state" in session:
        mr = ma.step_two_get_id_token_from_microsoft_url(
            request.url,
            session["microsoft_state"],
            f"{URL_PREFIX}/auth/microsoft_callback",
        )

        jprint({"path": "/auth/microsoft_callback", "method": request.method}, mr)

        session.pop("microsoft_nonce", None)
        session.pop("microsoft_state", None)

        if (
            "error" in mr
            and mr["error"]
            and "error_message" in mr
            and "login_required" in mr["error_message"]
        ):
            if "microsoft_retry" not in session or not session["microsoft_retry"]:
                session.pop("microsoft_retry", None)
                email = session["email"]
                mr = ma.step_one_get_redirect_url(
                    callback_url=f"{URL_PREFIX}/auth/microsoft_callback",
                    login_hint=email["email"],
                    domain_hint=email["domain"],
                    override_prompt="consent",
                )
                if "error" in mr and mr["error"] == False and "url" in mr:
                    session["microsoft_state"] = mr["state"]
                    session["microsoft_nonce"] = mr["nonce"]
                    session["microsoft_retry"] = True
                    return redirect(mr["url"])
                else:
                    return returnError(403)

        if "id_token" not in mr:
            return return_sign_in(
                is_error=True,
                fail_message="Microsoft account sign in failed, please continue to try again with an email code",
                force_email=True,
            )

        id_token = mr["id_token"]

        if "amr" not in id_token or "mfa" not in id_token["amr"]:
            return return_sign_in(
                is_error=True,
                fail_message="Microsoft account missing multifactor authentication, please continue to try again with an email code",
                force_email=True,
            )

        email = email_parts(id_token["upn"])
        ve = valid_email(email, debug=DEBUG)
        if not ve["valid"]:
            return return_sign_in(
                is_error=True,
                fail_message="Microsoft account sign in failed, please continue to try again with an email code",
                force_email=True,
            )

        sub = sso_oidc.write_user_sub(
            microsoft_sub=id_token["sub"], email=email["email"]
        )
        session["sub"] = sub
        session["email"] = email
        session["pf_quality"] = FactorQuality.high
        session["mfa_quality"] = FactorQuality.none

        user_attributes = sso_oidc.get_subs_attributes(
            sub,
            attributes=["microsoft_init", "display_name"],
            set_attribute_none=True,
        )

        if not user_attributes["microsoft_init"]:
            if not user_attributes["display_name"]:
                user_attributes["display_name"] = (
                    id_token["name"]
                    if "name" in id_token
                    else (id_token["given_name"] if "given_name" in id_token else None)
                )
            sso_oidc.update_subs_attributes(
                sub,
                {
                    "display_name": user_attributes["display_name"],
                    "microsoft_init": True,
                },
            )

        session.permanent = True
        session["signed_in"] = True
        session["display_name"] = (
            user_attributes["display_name"]
            if "display_name" in user_attributes and user_attributes["display_name"]
            else None
        )
        session["init_country"] = client_country()

        jprint(
            {
                "sub": session["sub"],
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "client_ip": client_ip(),
                "client_country": session["init_country"],
                "microsoft_auth_ip": id_token["ipaddr"]
                if "ipaddr" in id_token
                else None,
                "action": "microsoft-sign-in-successful",
                "browser_cookie_value": browser_cookie_value,
            }
        )

        if "oidc_redirect_uri" in session and session["oidc_redirect_uri"]:
            redirect_url = "/auth/oidc"

        return config_remember_me_cookie(
            session["email"]["email"], redirect(redirect_url)
        )

    return redirect(redirect_url)


@app.route("/auth/google_callback", methods=["GET", "POST"])
@SetBrowserCookie
def google_callback():
    redirect_url = "/dashboard"
    browser_cookie_value = get_browser_cookie_value()

    if not ga:
        return returnError(501, "Not implemented")

    if "google_state" in session:
        gr = ga.step_two_get_id_token_from_google_url(
            request.url, session["google_state"], f"{URL_PREFIX}/auth/google_callback"
        )

        jprint({"path": "/auth/google_callback", "method": request.method}, gr)

        session.pop("google_nonce", None)
        session.pop("google_state", None)

        if (
            "error" in gr
            and gr["error"]
            and gr["error_message"]
            and "interaction_required" in gr["error_message"]
        ) or (
            "error_subtype" in gr
            and gr["error_subtype"]
            and "access_denied" in gr["error_subtype"]
        ):
            if "google_retry" not in session or not session["google_retry"]:
                session.pop("google_retry", None)
                email = session["email"]
                gr = ga.step_one_get_redirect_url(
                    callback_url=f"{URL_PREFIX}/auth/google_callback",
                    login_hint=email["email"],
                    hd_domain_hint=email["domain"],
                    override_prompt="consent",
                )
                if "error" in gr and gr["error"] == False and "url" in gr:
                    session["google_nonce"] = gr["nonce"]
                    session["google_state"] = gr["state"]
                    session["google_retry"] = True
                    return redirect(gr["url"])
                else:
                    return returnError(403)

        if "error" in gr and gr["error"]:
            return return_sign_in(
                is_error=True,
                fail_message="Google account sign in failed, please continue to try again with an email code",
                force_email=True,
            )

        if "id_token" in gr:
            id_token = gr["id_token"]

            if not id_token["email_verified"]:
                jprint("google_callback: email_verified is false", {"email": email})
                return return_sign_in(
                    is_error=True,
                    fail_message="Google account sign in failed, please continue to try again with an email code",
                    force_email=True,
                )

            email = email_parts(id_token["email"])
            ve = valid_email(email, debug=DEBUG)
            if not ve["valid"]:
                jprint(
                    "google_callback: valid_email returned invalid", {"email": email}
                )
                return return_sign_in(
                    is_error=True,
                    fail_message="Google account sign in failed, please continue to try again with an email code",
                    force_email=True,
                )

            sub = sso_oidc.write_user_sub(
                google_sub=id_token["sub"], email=email["email"]
            )
            session["sub"] = sub
            session["email"] = email
            session["pf_quality"] = FactorQuality.high
            session["mfa_quality"] = FactorQuality.none

            user_attributes = sso_oidc.get_subs_attributes(
                sub,
                attributes=["google_init", "display_name"],
                set_attribute_none=True,
            )

            if not user_attributes["google_init"]:
                if not user_attributes["display_name"]:
                    user_attributes["display_name"] = (
                        id_token["name"]
                        if "name" in id_token
                        else (
                            id_token["given_name"] if "given_name" in id_token else None
                        )
                    )
                sso_oidc.update_subs_attributes(
                    sub,
                    {
                        "display_name": user_attributes["display_name"],
                        "google_init": True,
                    },
                )

            session.permanent = True
            session["signed_in"] = True
            session["display_name"] = (
                user_attributes["display_name"]
                if "display_name" in user_attributes and user_attributes["display_name"]
                else None
            )
            session["init_country"] = client_country()

            if "oidc_redirect_client" in session and session["oidc_redirect_client"]:
                redirect_url = "/auth/oidc"

            jprint(
                {
                    "sub": session["sub"],
                    "email": session["email"]["email"]
                    if "email" in session and "email" in session["email"]
                    else "",
                    "client_ip": client_ip(),
                    "client_country": session["init_country"],
                    "action": "google-sign-in-successful",
                    "browser_cookie_value": browser_cookie_value,
                    "redirect_url": redirect_url,
                }
            )

            return config_remember_me_cookie(
                session["email"]["email"], redirect(redirect_url)
            )

    return redirect(redirect_url)


@app.route("/auth/oidc", methods=["GET", "POST"])
@SetBrowserCookie
def auth_oidc():
    client = {"ok": False}

    # ==
    # get tmp_client_id
    # ==
    tmp_client_id = None
    if "client_id" in request.args:
        tmp_client_id = request.args["client_id"]
    elif "client_id" in request.form:
        tmp_client_id = request.form["client_id"]
    elif "oidc_client_id" in session:
        tmp_client_id = session["oidc_client_id"]

    # ==
    # get tmp_implicit_jwt
    # ==
    tmp_implicit_jwt = False
    if tmp_client_id is not None:
        client = sso_oidc.get_client(tmp_client_id)
        if not client["ok"]:
            return redirect("/error?type=client-id-unknown")
        session["oidc_client_id"] = tmp_client_id
        if "implicit_jwt" in client:
            tmp_implicit_jwt = client["implicit_jwt"]

    # ==
    # get tmp_response_types
    # ==
    tmp_response_types = None
    if tmp_implicit_jwt:
        tmp_response_types = "id_token"
    else:
        if "response_type" in request.args:
            tmp_response_types = request.args["response_type"]
        elif "response_type" in request.form:
            tmp_response_types = request.form["response_type"]
        elif "oidc_response_types" in session:
            tmp_response_types = session["oidc_response_types"]

    tmp_is_code = False
    tmp_is_token = False
    tmp_is_id_token = False

    if tmp_response_types is not None:
        if "code" in tmp_response_types:
            tmp_is_code = True
        if "id_token" in tmp_response_types:
            tmp_is_id_token = True
        if re.search(r"(?<!id_)token", tmp_response_types):
            tmp_is_token = True

    if not tmp_is_code and not tmp_is_token and not tmp_is_id_token:
        return redirect("/error?type=response_type-not-set")
    session["oidc_response_types"] = tmp_response_types

    # ==
    # get tmp_response_mode
    # ==
    tmp_response_mode = None
    if client["ok"] and "response_mode" in client and client["response_mode"]:
        tmp_response_mode = client["response_mode"]
    else:
        if "response_mode" in request.args:
            tmp_response_mode = request.args["response_mode"]
        elif "response_mode" in request.form:
            tmp_response_mode = request.form["response_mode"]
        elif "oidc_response_mode" in session:
            tmp_response_mode = session["oidc_response_mode"]

    tmp_form_resp = False
    tmp_uri_get_resp = False

    if tmp_response_mode:
        tmp_form_resp = tmp_response_mode == "form_post"
        tmp_uri_get_resp = tmp_response_mode == "uri_get"
        session["oidc_response_mode"] = tmp_response_mode

    # ==
    # get raw_redirect_url
    # ==
    raw_redirect_url = None
    redirect_url_attribute = "redirect_uri"
    if (
        client["ok"]
        and "redirect_uri_override" in client
        and client["redirect_uri_override"]
    ):
        redirect_url_attribute = client["redirect_uri_override"]

    if redirect_url_attribute in request.args:
        raw_redirect_url = request.args[redirect_url_attribute]
    elif redirect_url_attribute in request.form:
        raw_redirect_url = request.form[redirect_url_attribute]
    elif "oidc_redirect_uri" in session:
        raw_redirect_url = session["oidc_redirect_uri"]

    # ==
    # get tmp_redirect_url
    # ==
    session.pop("oidc_redirect_client", None)
    session.pop("oidc_redirect_uri", None)

    tmp_redirect_url = None
    if client["ok"]:
        session["oidc_redirect_client"] = True
        if "redirect_url_override" in client and client["redirect_url_override"]:
            urlor = client["redirect_url_override"]
            if raw_redirect_url is not None:
                uripf = "&" if "?" in urlor else "?"
                tmp_redirect_url = f"{urlor}{uripf}{redirect_url_attribute}={raw_redirect_url}".replace(
                    "?&", "?"
                )
            else:
                tmp_redirect_url = urlor
        elif (
            raw_redirect_url is not None
            and raw_redirect_url
            and "redirect_urls" in client
        ):
            for redurl in client["redirect_urls"]:
                if raw_redirect_url == redurl or raw_redirect_url.startswith(redurl):
                    tmp_redirect_url = raw_redirect_url
                    break
            if tmp_redirect_url is None and len(client["redirect_urls"]) > 0:
                tmp_redirect_url = client["redirect_urls"][0]
        elif (
            raw_redirect_url is None
            and "redirect_urls" in client
            and len(client["redirect_urls"]) > 0
        ):
            tmp_redirect_url = client["redirect_urls"][0]

    session["oidc_redirect_uri"] = (
        tmp_redirect_url if tmp_redirect_url is not None else "/sign-in"
    )

    # ==
    # get tmp_scope
    # ==
    tmp_scope = None
    if client["ok"] and "scope_override" in client and client["scope_override"]:
        tmp_scope = client["scope_override"]
    else:
        if "scope" in request.args:
            tmp_scope = request.args["scope"]
        elif "scope" in request.form:
            tmp_scope = request.form["scope"]
        elif "oidc_scope" in session:
            tmp_scope = session["oidc_scope"]
    if tmp_scope is not None:
        tmp_scope = sso_oidc.sanitise_scopes(tmp_scope)
    session["oidc_scope"] = tmp_scope

    # ==
    # get tmp_state
    # ==
    tmp_state = None
    if "state" in request.args:
        tmp_state = request.args["state"]
    elif "state" in request.form:
        tmp_state = request.form["state"]
    elif "oidc_state" in session:
        tmp_state = session["oidc_state"]
    session["oidc_state"] = tmp_state

    # ==
    # get tmp_nonce
    # ==
    tmp_nonce = None
    if "nonce" in request.args:
        tmp_nonce = request.args["nonce"]
    elif "nonce" in request.form:
        tmp_nonce = request.form["nonce"]
    elif "oidc_nonce" in session:
        tmp_nonce = session["oidc_nonce"]
    session["oidc_nonce"] = tmp_nonce

    # ==
    # ** If signed in... **
    # ==
    if "signed_in" in session and session["signed_in"] and "sub" in session:
        gus = sso_oidc.get_user_sub(sub=session["sub"])

        ve = valid_email(gus["email"], client, debug=DEBUG)
        if ve["valid"] == False:
            app_name = (
                client["name"]
                if "name" in client and client["name"]
                else "the requested application"
            )
            app_contact = (
                client["contact"]
                if "contact" in client and client["contact"]
                else "the application provider"
            )

            error_message = f"You do not have access to {app_name}. If you believe this is incorrect, contact {app_contact}."

            tau = (
                client["sign_in_url"]
                if "sign_in_url" in client and client["sign_in_url"]
                else (
                    client["app_url"]
                    if "app_url" in client and client["app_url"]
                    else None
                )
            )

            return returnError(
                403,
                "No access",
                error_message,
                override_try_again_url=tau,
                include_try_again=True,
            )

        auth_code = None
        if tmp_is_code:
            auth_code = sso_oidc.create_auth_code(
                client["client_id"],
                session["sub"],
                session["oidc_scope"],
                session["pf_quality"],
                session["mfa_quality"],
                nonce=session["oidc_nonce"],
            )

        access_token = None
        if tmp_is_token:
            access_token = sso_oidc.create_access_code(
                client["client_id"],
                session["oidc_scope"],
                session["pf_quality"],
                session["mfa_quality"],
                nonce=session["oidc_nonce"],
            )

        id_token = None
        if tmp_is_id_token:
            id_token = sso_oidc.generate_id_token(
                client_id=client["client_id"],
                user=gus,
                scopes=session["oidc_scope"],
                pf_quality=session["pf_quality"],
                mfa_quality=session["mfa_quality"],
                nonce=session["oidc_nonce"],
                jwt_attributes=(
                    client["jwt_attributes"] if "jwt_attributes" in client else None
                ),
                jwt_algorithm_override=(
                    client["jwt_algorithm_override"]
                    if "jwt_algorithm_override" in client
                    else None
                ),
                jwt_secret=(client["jwt_secret"] if "jwt_secret" in client else None),
                unique_request_id=(
                    client["jwt_unique_request_id"]
                    if "jwt_unique_request_id" in client
                    else False
                ),
            )

        redirect_string = session["oidc_redirect_uri"] + (
            "?" if "?" not in session["oidc_redirect_uri"] else "&"
        )

        if auth_code:
            redirect_string += f"code={auth_code}&"
        if access_token:
            redirect_string += f"token={access_token}&"
        if id_token:
            itq = "id_token"
            if (
                "id_token_querystring_override" in client
                and client["id_token_querystring_override"]
            ):
                itq = client["id_token_querystring_override"]
            redirect_string += f"{itq}={id_token}&"

        if "oidc_state" in session:
            redirect_string += f"state={session['oidc_state']}"

        redirect_string = redirect_string.strip("&")

        to_pop = []
        for s in session:
            if s.startswith("oidc_"):
                to_pop.append(s)
        for x in to_pop:
            session.pop(x, None)
    # ==
    # ** End if signed in... **
    # ==
    elif client["client_id"]:
        redirect_string = f"/sign-in?to_app={client['client_id']}"

    return redirect(redirect_string)


@app.route("/", methods=["GET"])
def root():
    if "signed_in" in session and session["signed_in"]:
        return redirect("/dashboard")
    return renderTemplate(
        "index.html", {"title": "Start", "session": session if session else {}}
    )


@app.route("/sign-out", methods=["GET"])
def signout(country_missmatch: bool = False):
    if "from_app" in request.args:
        page_params = {}
        client = sso_oidc.get_client(request.args.get("from_app", None))
        if client["ok"]:
            if "name" in client:
                page_params.update({"from_app_name": client["name"]})
        return make_response(renderTemplate("sign-out.html", page_params))

    if session:
        for key in list(session.keys()):
            session.pop(key)
        session.clear()

    if country_missmatch:
        return returnError(
            status_code=401,
            override_title="Unauthorised travel detected",
            override_message="Please try again",
        )

    redirect_url: str = "/"

    to_client = get_request_val(
        "to_client",
        use_session=True,
        use_querystrings=True,
        use_posted_data=True,
    )
    if to_client:
        client = sso_oidc.get_client(to_client)
        if client["ok"] and "app_url" in client:
            redirect_url = client["app_url"]

    return redirect(redirect_url)


@app.route("/dashboard", methods=["GET"])
@UserShouldBeSignedIn
@SetBrowserCookie
def dashboard():
    cc = country_check()
    if cc:
        return cc

    allowed_apps = {}
    all_clients = sso_oidc.get_clients()
    for client in all_clients:
        ve = valid_email(session["email"]["email"], all_clients[client], debug=DEBUG)
        if ve["valid"]:
            name = (
                all_clients[client]["name"] if "name" in all_clients[client] else None
            )

            button_text = (
                all_clients[client]["dashboard_button_override"]
                if "dashboard_button_override" in all_clients[client]
                else f"Open {name}"
            )

            description = (
                all_clients[client]["description"]
                if "description" in all_clients[client]
                else None
            )

            app_url = (
                all_clients[client]["app_url"]
                if "app_url" in all_clients[client]
                else None
            )

            sign_in_url = (
                all_clients[client]["sign_in_url"]
                if "sign_in_url" in all_clients[client]
                else app_url
            )

            dashboard_display = (
                all_clients[client]["dashboard_display"]
                if "dashboard_display" in all_clients[client]
                else True
            )

            allowed_apps[client] = {
                "name": name,
                "description": description,
                "sign_in_url": sign_in_url,
                "button_text": button_text,
                "dashboard_display": dashboard_display,
            }

    return renderTemplate(
        "dashboard.html",
        {
            "session": session,
            "allowed_apps": allowed_apps,
            "title": "Dashboard",
            "nav_item": "dashboard",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/help", methods=["GET"])
def help():
    return renderTemplate(
        "help.html",
        {
            "session": session,
            "title": "Help",
            "nav_item": "help",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/terms", methods=["GET"])
def terms():
    return renderTemplate(
        "terms.html",
        {
            "session": session,
            "title": "Terms of Service",
            "nav_item": "terms",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/privacy-notice", methods=["GET"])
def privacy_notice():
    return renderTemplate(
        "privacy-notice.html",
        {
            "session": session,
            "title": "Privacy Notice",
            "nav_item": "privacy-notice",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/profile/saved", methods=["GET"])
@UserShouldBeSignedIn
@SetBrowserCookie
def profile_saved():
    return renderTemplate(
        "profile-saved.html",
        {
            "session": session,
            "title": "Profile Saved",
            "nav_item": "profile",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/profile", methods=["GET", "POST"])
@UserShouldBeSignedIn
@CheckCSRFSession
@SetBrowserCookie
def profile():
    if "sub" not in session:
        return redirect("/sign-in")
    sub = session["sub"]

    user_attributes = sso_oidc.get_subs_attributes(
        sub,
        attributes=["display_name", "sms_number"],
        set_attribute_none=True,
    )

    # jprint({"path": "/profile", "method": request.method}, user_attributes)

    if request.method == "POST":
        keys = ["display-name", "sms-number"]
        params = get_request_vals(*keys, use_posted_data=True)
        for field in keys:
            if field not in params:
                return returnError(403)

        new_display_name = sanitise_string(params["display-name"])
        new_sms_number = sanitise_string(
            params["sms-number"],
            allow_letters=False,
            allow_space=False,
            allow_single_quotes=False,
            allow_hyphen=False,
            additional_allowed_chars=["+"],
            max_length=15,
        )

        session["display_name"] = new_display_name
        user_attributes["display_name"] = new_display_name

        # TODO: check if new number is different than old,
        # if so, then send a code to validate new number

        user_attributes["sms_number"] = new_sms_number

        save_success = sso_oidc.update_subs_attributes(
            sub, {"display_name": new_display_name, "sms_number": new_sms_number}
        )

        if save_success:
            return redirect("/profile/saved")
        else:
            return returnError()

    display_name = (
        user_attributes["display_name"] if "display_name" in user_attributes else ""
    )

    sms_number = (
        user_attributes["sms_number"] if "sms_number" in user_attributes else ""
    )

    return renderTemplate(
        "profile.html",
        {
            "csrf_form": get_csrf_session(),
            "session": session,
            "display_name": display_name,
            "sms_number": sms_number,
            "title": "Profile",
            "nav_item": "profile",
            "IS_ADMIN": IS_ADMIN,
        },
    )


def country_check():
    browser_cookie_value = get_browser_cookie_value()
    country = client_country()
    init_country = session.get("init_country", None)
    if init_country and init_country != "Unknown" and init_country != country:
        jprint(
            {
                "sub": session["sub"],
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "client_ip": client_ip(),
                "client_country": country,
                "action": "country-missmatch-signout",
                "init_country": init_country,
                "browser_cookie_value": browser_cookie_value,
            }
        )
        return signout(country_missmatch=True)
    return None


def get_remember_me_cookie_value():
    email_raw = request.cookies.get(COOKIE_NAME_REMEMBERME, "").strip('"').strip()
    if email_raw:
        email_object = email_parts(email_raw)
        if email_object:
            return email_object["email"]
    return None


def config_remember_me_cookie(email: str, response):
    if "remember_me" in session:
        rem = session["remember_me"]
        session.pop("remember_me")
        if email and rem:
            return add_remember_me_cookie(email, response)
    return remove_remember_me_cookie(response)


def add_remember_me_cookie(email: str, response):
    if email:
        response.set_cookie(
            COOKIE_NAME_REMEMBERME,
            email.strip('"').strip(),
            secure=IS_HTTPS,
            httponly=True,
            samesite="Lax",
            max_age=31536000,
        )
    return response


def remove_remember_me_cookie(response):
    response.delete_cookie(COOKIE_NAME_REMEMBERME)
    return response


@app.route("/sign-in", methods=["GET", "POST"])
@CheckCSRFSession
@SetBrowserCookie
def signin():
    browser_cookie_value = get_browser_cookie_value()
    c_ip = client_ip()
    country = client_country()
    code_fail = False
    signed_in = False

    redirect_url = "/dashboard"
    to_app = get_request_val(
        "to_app",
        use_posted_data=True,
        use_querystrings=True,
        use_session=True,
    )
    if to_app:
        if sso_oidc.is_client(to_app):
            client = sso_oidc.get_client(to_app)

            # redirect_url = None
            # if session.get("oidc_redirect_client", False):
            #     redirect_url = session.get("oidc_redirect_uri", None)
            #     jprint(
            #         "oidc_redirect_client is True, using oidc_redirect_uri:",
            #         redirect_url,
            #     )
            # if redirect_url is None:
            redirect_url = (
                client["sign_in_url"]
                if "sign_in_url" in client and client["sign_in_url"]
                else (
                    client["app_url"]
                    if "app_url" in client and client["app_url"]
                    else None
                )
            )

    if request.method != "POST":
        if "signed_in" in session and session["signed_in"]:
            cc = country_check()
            if cc:
                return cc

            return redirect(redirect_url)
        else:
            return return_sign_in()

    if not browser_cookie_value:
        jprint(
            {"path": "/profile", "method": request.method},
            "browser_cookie_value not found in request",
        )
        return returnError(425)

    params = get_request_vals(
        "email",
        "remember_me",
        "code",
        "code_type",
        use_posted_data=True,
        use_session=True,
    )
    if "email" not in params or not params["email"]:
        jprint("signin: email not in params", {"params": params})
        return return_sign_in(is_error=True)

    # if not attempting a code verification
    if "code" not in params:
        email = email_parts(params["email"])

        ve = valid_email(email, debug=DEBUG)
        if not ve["valid"]:
            jprint("signin: email_verified is false", {"email": email})
            return return_sign_in(is_error=True)

        auth_type = ve["auth_type"]
        if ve["user_type"] is None or ve["user_type"] != "user":
            return returnError(403)

        session["email"] = email

        remember_me = False
        if "remember_me" in params:
            if str(params["remember_me"]).lower() == "true":
                remember_me = True
        session["remember_me"] = remember_me

        force_email = False
        if "force_email" in session:
            force_email = session["force_email"]
            session.pop("force_email", None)

        if not force_email and ga and auth_type == "google":
            gr = ga.step_one_get_redirect_url(
                callback_url=f"{URL_PREFIX}/auth/google_callback",
                login_hint=email["email"],
                hd_domain_hint=email["domain"],
            )
            if "error" in gr and gr["error"] == False and "url" in gr:
                session["google_state"] = gr["state"]
                session["google_nonce"] = gr["nonce"]
                return redirect(gr["url"])
            else:
                return returnError(403)

        if not force_email and ma and auth_type == "microsoft":
            mr = ma.step_one_get_redirect_url(
                callback_url=f"{URL_PREFIX}/auth/microsoft_callback",
                login_hint=email["email"],
                domain_hint=email["domain"],
            )
            if "error" in mr and mr["error"] == False and "url" in mr:
                session["microsoft_state"] = mr["state"]
                session["microsoft_nonce"] = mr["nonce"]
                return redirect(mr["url"])
            else:
                return returnError(403)

        # if not Microsoft or Google, then fallback to email code

        code = random_string(9, True).lower()
        pretty_code = f"{code[:3]}-{code[3:6]}-{code[6:]}"

        sub = sso_oidc.write_user_sub(email=email["email"])
        session["sub"] = sub
        user_attributes = sso_oidc.get_subs_attributes(
            sub,
            attributes=["display_name", "sms_number"],
            set_attribute_none=True,
        )

        if user_attributes["sms_number"] and len(user_attributes["sms_number"]) > 1:
            session["sms_auth_required"] = True
        else:
            session["sms_auth_required"] = False

        if USE_NOTIFY:
            try:
                response = notifications_client.send_email_notification(
                    email_address=email["email"],
                    template_id=env_var("NOTIFY_EMAIL_AUTH_CODE_TEMPLATE"),
                    personalisation={
                        "auth_code": pretty_code,
                        "display_name": user_attributes["display_name"]
                        if "display_name" in user_attributes
                        and user_attributes["display_name"]
                        else session["email"]["email"],
                        "obfuscated_ip ": (".".join(c_ip.split(".")[:-1]) + ".*")
                        if "." in c_ip
                        else (":".join(c_ip.split(":")[:-1]) + ":*")
                        if ":" in c_ip
                        else "Unknown",
                        "country": country,
                        "domain": DOMAIN,
                        "browser_guess": guess_browser(
                            request.headers["true-user-agent"]
                            if "true-user-agent" in request.headers
                            else (
                                request.headers["User-Agent"]
                                if "User-Agent" in request.headers
                                else ""
                            )
                        ),
                    },
                )
            except Exception as e:
                jprint({"error": e, "Error": traceback.format_exc()})
                return returnError(500)

        session["email-sign-in-code"] = code

        jprint(
            {
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "client_ip": c_ip,
                "client_country": country,
                "action": "sign-in-request-email",
                "pretty_code": pretty_code if DEBUG else "REDACTED",
                "browser_cookie_value": browser_cookie_value,
            }
        )

        return return_sign_in(is_code=True, code_type="email")
        # end code verification

    user_attributes = {}
    if "sub" in session:
        user_attributes = sso_oidc.get_subs_attributes(
            session["sub"],
            attributes=["display_name", "sms_number"],
            set_attribute_none=True,
        )

    if "code" in params:
        code = params["code"].lower().replace("-", "").strip()
        code_type = params["code_type"]
        if code_type not in ["email", "phone"]:
            return returnError(403)

        sms_auth_required = False
        if "sms_auth_required" in session and session["sms_auth_required"]:
            sms_auth_required = session["sms_auth_required"]

        if code_type == "phone" and "sms-sign-in-code" in session:
            if code != session["sms-sign-in-code"]:
                jprint(
                    {
                        "email": session["email"]["email"]
                        if "email" in session and "email" in session["email"]
                        else "",
                        "client_ip": client_ip(),
                        "client_country": country,
                        "action": "code-fail",
                        "browser_cookie_value": browser_cookie_value,
                    }
                )
                return return_sign_in(is_code=True, code_type="phone", code_fail=True)
            else:
                if (
                    "email-sign-in-complete" in session
                    and session["email-sign-in-complete"]
                ):
                    session.pop("email-sign-in-complete")
                    session.pop("sms-sign-in-code")
                    session["mfa_quality"] = FactorQuality.medium
                    session["init_country"] = country
                    signed_in = True
                else:
                    return redirect("/sign-in")

        if code_type == "email":
            if code != session["email-sign-in-code"]:
                jprint(
                    json.dumps(
                        {
                            "code": code,
                            "email-sign-in-code": session["email-sign-in-code"],
                            "email": session["email"]["email"]
                            if "email" in session and "email" in session["email"]
                            else "",
                            "client_ip": client_ip(),
                            "client_country": country,
                            "action": "code-fail",
                            "browser_cookie_value": browser_cookie_value,
                        },
                        default=str,
                    )
                )
                return return_sign_in(is_code=True, code_type="email", code_fail=True)
            else:
                session.pop("email-sign-in-code")
                session["email-sign-in-complete"] = True
                session["mfa_quality"] = FactorQuality.none
                session["pf_quality"] = FactorQuality.medium
                session["init_country"] = country

                if not sms_auth_required:
                    signed_in = True
                else:
                    if (
                        "sms_number" not in user_attributes
                        or not user_attributes["sms_number"]
                    ):
                        return redirect("/sign-in")

                    code = random_string(6, only_numbers=True)
                    pretty_code = f"{code[:3]}-{code[3:6]}"

                    if USE_NOTIFY:
                        try:
                            response = notifications_client.send_sms_notification(
                                phone_number=user_attributes["sms_number"],
                                template_id=env_var("NOTIFY_SMS_AUTH_CODE_TEMPLATE"),
                                personalisation={
                                    "sms_auth_code": pretty_code,
                                    "display_name": user_attributes["display_name"]
                                    if "display_name" in user_attributes
                                    and user_attributes["display_name"]
                                    else session["email"]["email"],
                                },
                            )
                        except Exception as e:
                            jprint({"error": e, "Error": traceback.format_exc()})
                            return returnError(500)

                    session["sms-sign-in-code"] = code

                    jprint(
                        {
                            "email": session["email"]["email"]
                            if "email" in session and "email" in session["email"]
                            else "",
                            "client_ip": c_ip,
                            "client_country": country,
                            "action": "sign-in-request-sms",
                            "sms_number": user_attributes["sms_number"]
                            if DEBUG
                            else "REDACTED",
                            "pretty_code": pretty_code if DEBUG else "REDACTED",
                            "browser_cookie_value": browser_cookie_value,
                        }
                    )

                    return return_sign_in(
                        is_code=True, code_type="phone", code_fail=code_fail
                    )

    if signed_in or ("signed_in" in session and session["signed_in"]):
        cc = country_check()
        if cc:
            return cc

        session.permanent = True
        session["signed_in"] = True
        session["display_name"] = (
            user_attributes["display_name"]
            if "display_name" in user_attributes and user_attributes["display_name"]
            else None
        )

        jprint(
            {
                "sub": session["sub"],
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "client_ip": client_ip(),
                "client_country": country,
                "action": "sign-in-successful",
                "browser_cookie_value": browser_cookie_value,
            }
        )

        return config_remember_me_cookie(
            session["email"]["email"], redirect(redirect_url)
        )

    # shouldn't get to here
    return redirect("/sign-in")


def return_sign_in(
    is_error: bool = False,
    code_fail: bool = False,
    is_code: bool = False,
    code_type: str = "email",
    fail_message: str = None,
    force_email: bool = False,
):
    session["force_email"] = force_email

    erm = get_remember_me_cookie_value()

    to_app = get_request_val(
        "to_app", use_posted_data=True, use_querystrings=True, use_session=True
    )

    jprint(
        {
            "is_error": is_error,
            "code_fail": code_fail,
            "is_code": is_code,
            "code_type": code_type,
            "fail_message": fail_message,
            "force_email": force_email,
            "erm": erm,
            "to_app": to_app,
        }
    )

    page_params = {
        "email_remember_me": None if is_error or force_email else erm,
        "csrf_form": get_csrf_session(),
        "session": session,
        "is_error": is_error,
        "fail_message": fail_message or "Email address wasn't recognised",
        "force_email": force_email,
        "code_fail": code_fail,
        "title": code_type.title(),
        "form_url": "/sign-in",
        "code_type": code_type,
        "cancel_href": None,
    }

    client = sso_oidc.get_client(to_app)
    if client["ok"]:
        if "name" in client:
            page_params.update({"to_app_name": client["name"]})

        if "app_url" in client:
            page_params.update({"cancel_href": client["app_url"]})

        page_params.update({"form_url": f"/sign-in?to_app={client['client_id']}"})

    return make_response(
        renderTemplate("code.html" if is_code else "sign-in.html", page_params)
    )


def returnError(
    status_code: int = 500,
    override_title: str = None,
    override_message: str = None,
    override_try_again_url: str = None,
    include_try_again: bool = False,
):
    return make_response(
        renderTemplate(
            "error.html",
            {
                "title": (
                    override_title
                    if type(override_title) == str and override_title
                    else "Error"
                ),
                "try_again_url": (
                    (
                        override_try_again_url
                        if type(override_try_again_url) == str
                        and override_try_again_url
                        else request.path
                    )
                    if include_try_again
                    else None
                ),
                "session": session if session else {},
                "message": (
                    override_message
                    if type(override_message) == str and override_message
                    else None
                ),
            },
            status_code,
        )
    )


@app.route("/error")
def error():
    return returnError()


@app.route("/assets/<path:path>")
def _assets(path):
    if os.path.isdir(werkzeug.utils.safe_join(assets, path)):
        path = os.path.join(path, "index.html")
    resp = make_response(send_from_directory(assets, path))
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp


@app.route("/robots.txt")
def robot():
    response = make_response(
        f"""User-agent: Googlebot
User-agent: AdsBot-Google
User-agent: AdsBot-Google-Mobile
{'Allow' if IS_PROD else 'Disallow'}: /

User-agent: *
{'Allow' if IS_PROD else 'Disallow'}: /
""",
        200,
    )
    response.mimetype = "text/plain"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")))
