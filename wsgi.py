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
from jinja_helper import renderTemplate
from sso_data_access import read_file, write_file
from sso_utils import random_string, env_var, sanitise_string, jprint
from sso_email_check import valid_email
from email_helper import email_parts
from sso_ua import guess_browser

USE_NOTIFY = env_var("USE_NOTIFY", "f", return_bool=True)
IS_ADMIN = env_var("IS_ADMIN", "f", return_bool=True)
IS_HTTPS = env_var("IS_HTTPS", "f", return_bool=True)

COOKIE_PREFIX = "__Host-" if IS_HTTPS else ""
COOKIE_NAME_SESSION = f"{COOKIE_PREFIX}Session"
COOKIE_NAME_BROWSER = f"{COOKIE_PREFIX}Browser"
COOKIE_NAME_REMEMBERME = f"{COOKIE_PREFIX}RememberMe"

COOKIE_BROWSER_LENGTH = 64

CURRENT_SIGNING_KID = env_var("CURRENT_SIGNING_KID")

ENVIRONMENT = env_var("ENVIRONMENT", "development")
jprint("Starting wsgi.py - ENVIRONMENT:", ENVIRONMENT)

IS_PROD = "production" == ENVIRONMENT.lower()

app = Flask(__name__)

if ENVIRONMENT != "production":
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
    SECRET_KEY=env_var("FLASK_SECRET_KEY"),
    MAX_CONTENT_LENGTH=120 * 1024 * 1024,
)

assets = werkzeug.utils.safe_join(os.path.dirname(__file__), "assets")
alb_lambda_handler = make_lambda_handler(app)

DOMAIN = env_var("DOMAIN")
URL_PREFIX = f"http{'s' if IS_HTTPS else ''}://{DOMAIN}"

notifications_client = NotificationsAPIClient(env_var("NOTIFY_API_KEY"))


def client_ip():
    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        return request.environ["REMOTE_ADDR"]
    else:
        return request.environ["HTTP_X_FORWARDED_FOR"]


def lambda_handler(event, context):
    try:
        response = alb_lambda_handler(event, context)
        jprint(
            {
                "Request": event,
                "Response": {
                    "statusCode": response["statusCode"],
                    "headers": response["headers"],
                    "body_length": len(response["body"]),
                },
            }
        )
        return response
    except Exception as e:
        jprint({"Request": event, "Response": None, "Error": traceback.format_exc()})
        return {"statusCode": 500}


@app.route("/internal/<check>")
def health_check(check="health"):
    if check == "health":
        return "IMOK {}".format(check)
    else:
        return "FAIL dependencies"


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
            # "client_secret_basic",
            "client_secret_post",
            # "client_secret_jwt",
            # "none"
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
            "pf_quality",
            "mfa_quality",
        ],
        "code_challenge_methods_supported": ["plain"],
        "grant_types_supported": [
            "implicit",
            "authorization_code"
        ],
    }
    return jsonify(discovery)


@app.route("/auth/token", methods=["GET", "POST"])
def auth_token():

    required_keys = ["client_id", "client_secret", "code"]
    for key in required_keys:
        if key not in request.values:
            jprint(
                {
                    "path": "/auth/token",
                    "method": request.method,
                    "error": f"auth_token: key '{key}' does not exist, returning 401",
                }
            )
            return returnError(401)
        else:
            if len(request.values[key]) != 64 and len(request.values[key]) != 36:
                jprint(
                    {
                        "path": "/auth/token",
                        "method": request.method,
                        "error": f"auth_token: key '{key}' invalid, returning 401",
                    }
                )
                return returnError(401)

    client_id = request.values["client_id"]
    client_secret = request.values["client_secret"]
    auth_code = request.values["code"]

    gubac = sso_oidc.get_user_by_auth_code(client_id, client_secret, auth_code)
    if not gubac or "sub" not in gubac:
        jprint(
            {
                "path": "/auth/token",
                "method": request.method,
                "error": "auth_token: auth_code invalid, returning 401",
            }
        )
        return returnError(401)

    id_token = sso_oidc.generate_id_token(client_id, gubac, gubac["scopes"], session["pf_quality"], gubac["mfa_quality"])
    if id_token is None or not id_token:
        jprint(
            {
                "path": "/auth/token",
                "method": request.method,
                "error": "auth_token: id_token invalid, returning 401",
            }
        )
        return returnError(401)

    access_token = sso_oidc.create_access_code(sub, gubac["scopes"], session["pf_quality"], gubac["mfa_quality"])
    if access_token is None or not access_token:
        jprint(
            {
                "path": "/auth/token",
                "method": request.method,
                "error": "auth_token: access_token invalid, returning 401",
            }
        )
        return returnError(401)

    token = {
        "access_token": access_token,
        "id_token": id_token,  # .decode("utf-8"),
        "token_type": "bearer",
        "expires_in": time_now,
        "scope": " ".join(scopes),
    }
    return jsonify(token)


@app.route("/auth/profile", methods=["GET", "POST"])
def auth_profile():
    authorization = None
    id_token = None

    if "Authorization" in request.headers and " " in request.headers["Authorization"]:
        authorization = request.headers["Authorization"].split(" ")[1]
    elif "authorization" in request.values:
        authorization = request.values["authorization"]
    elif "token" in request.values:
        authorization = request.values["token"]
    elif "id_token" in request.values:
        id_token = request.values["id_token"]

    user_info = {
        "sub": None,
    }

    if authorization:
        gus = sso_oidc.get_user_by_access_code(authorization)

        if "email" in gus["scopes"] and "email" in gus:
            user_info["email"] = gus["email"]
            user_info["email_verified"] = True

        if "profile" in gus["scopes"]:
            dn = None
            if "attributes" in gus and "display_name" in gus["attributes"]:
                dn = gus["attributes"]["display_name"]
            user_info["display_name"] = dn
            user_info["nickname"] = dn

        if "sub" in gus:
            user_info["sub"] = gus["sub"]

    jprint({"path": "/auth/profile", "method": request.method, "user_info": user_info})

    return jsonify(user_info)


@app.route("/auth/oidc", methods=["GET", "POST"])
def auth_oidc():
    tmp_client_id = None
    tmp_redirect_url = None
    tmp_response_types = None
    tmp_response_mode = None

    tmp_is_code = False
    tmp_is_token = False
    tmp_is_id_token = False

    if "response_type" in request.values:
        tmp_response_types = request.values.get("response_type").lower()
    elif "oidc_response_types" in session:
        tmp_response_types = session["oidc_response_types"]

    if tmp_response_types:
        if "code" in tmp_response_types:
            tmp_is_code = True
        if "id_token" in tmp_response_types:
            tmp_is_id_token = True
        if re.search(r"(?<!id_)token", tmp_response_types):
            tmp_is_token = True

    if not tmp_is_code and not tmp_is_token and not tmp_is_id_token:
        return set_browser_cookie(redirect("/error?type=response_type-not-set"))

    if "response_mode" in request.values:
        tmp_response_mode = request.values.get("response_mode").lower()
    elif "oidc_response_mode" in session:
        tmp_response_mode = session["oidc_response_mode"]

    tmp_form_resp = tmp_response_mode == "form_post"

    if "client_id" in request.values:
        tmp_client_id = request.values.get("client_id")
    elif "oidc_client_id" in session:
        tmp_client_id = session["oidc_client_id"]

    if tmp_client_id:
        clients = sso_oidc.get_clients()
        if tmp_client_id not in clients:
            return set_browser_cookie(redirect("/error?type=client-id-unknown"))
        client = clients[tmp_client_id]

        raw_redirect_url = None
        if "redirect_uri" in request.values:
            raw_redirect_url = request.values.get("redirect_uri")
        elif "oidc_redirect_uri" in session:
            raw_redirect_url = session["oidc_redirect_uri"]

        jprint(
            {
                "path": "/auth/oidc",
                "method": request.method,
                "raw_redirect_url": raw_redirect_url,
            }
        )

        # https://nonprod.security.gov.uk/api/auth/oidc_callback?redirect=/signed-in.html

        if "redirect_urls" in client:
            if raw_redirect_url:
                for redurl in client["redirect_urls"]:
                    if raw_redirect_url == redurl or raw_redirect_url.startswith(
                        redurl
                    ):
                        tmp_redirect_url = raw_redirect_url
            if not tmp_redirect_url:
                tmp_redirect_url = client["redirect_urls"][0]

        session["oidc_redirect_uri"] = tmp_redirect_url
        session["oidc_client_id"] = tmp_client_id
        session["oidc_response_mode"] = tmp_response_mode
        session["oidc_response_types"] = tmp_response_types

    tmp_scope = None
    if "scope" in request.values:
        tmp_scope = request.values.get("scope")
    elif "oidc_scope" in session:
        tmp_scope = session["oidc_scope"]

    session["oidc_scope"] = sso_oidc.sanitise_scopes(tmp_scope)

    if "state" in request.values:
        session["oidc_state"] = request.values.get("state")

    if "nonce" in request.values:
        session["oidc_nonce"] = request.values.get("nonce")

    redirect_string = "/sign-in"

    jprint(
        {
            "path": "/auth/oidc",
            "method": request.method,
            "tmp_redirect_url": tmp_redirect_url,
        }
    )

    if "signed_in" in session and session["signed_in"] and "sub" in session:
        auth_code = None
        if tmp_is_code:
            auth_code = sso_oidc.create_auth_code(tmp_client_id, session["sub"], session["oidc_scope"], session["pf_quality"], session["mfa_quality"])

        access_token = None
        if tmp_is_token:
            access_token = sso_oidc.create_access_code(session["sub"], session["oidc_scope"], session["pf_quality"], session["mfa_quality"])

        id_token = None
        if tmp_is_id_token:
            gus = get_user_sub(sub=session["sub"])
            id_token = sso_oidc.generate_id_token(tmp_client_id, gus, session["oidc_scope"], session["pf_quality"], session["mfa_quality"])

        redirect_string = tmp_redirect_url
        redirect_string += "?" if "?" not in tmp_redirect_url else "&"

        if auth_code:
            redirect_string += f"code={auth_code}&"
        if access_token:
            redirect_string += f"token={access_token}&"
        if id_token:
            redirect_string += f"id_token={id_token}&"

        if "oidc_state" in session:
            redirect_string += f"state={session['oidc_state']}"
            session.pop("oidc_state", None)

        session.pop("oidc_client_id", None)
        session.pop("oidc_redirect_uri", None)
        session.pop("oidc_response_mode", None)
        session.pop("oidc_response_types", None)
        session.pop("oidc_nonce", None)
        session.pop("oidc_scope", None)
    elif tmp_client_id:
        redirect_string = f"/sign-in?to_app={tmp_client_id}"

    return set_browser_cookie(redirect(redirect_string))


@app.route("/", methods=["GET"])
def root():
    if "signed_in" in session and session["signed_in"]:
        return redirect("/dashboard")
    return renderTemplate("index.html", {"title": "Start"})


@app.route("/sign-out", methods=["GET"])
def signout():
    if session:
        for key in list(session.keys()):
            session.pop(key)
        session.clear()

    redirect_url = "/"

    clients = sso_oidc.get_clients()

    if "to_client" in request.values:
        tmp_client_id = request.values["to_client"]
        if tmp_client_id in clients:
            client = clients[tmp_client_id]
            if client and "app_url" in client:
                redirect_url = client["app_url"]

    return redirect(redirect_url)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "signed_in" in session and session["signed_in"]:

        allowed_apps = {}
        all_clients = sso_oidc.get_clients()
        for client in all_clients:
            if valid_email(session["email"]["email"], all_clients[client]):
                name = (
                    all_clients[client]["name"]
                    if "name" in all_clients[client]
                    else None
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

                allowed_apps[client] = {
                    "name": name,
                    "description": description,
                    "sign_in_url": sign_in_url,
                    "button_text": button_text,
                }

        # session["csrf"] = random_string()
        return renderTemplate(
            "dashboard.html",
            {
                # "csrf_form": session["csrf"],
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "display_name": session["display_name"]
                if "display_name" in session
                else session["email"]["email"],
                "allowed_apps": allowed_apps,
                "title": "Dashboard",
                "nav_item": "dashboard",
                "IS_ADMIN": IS_ADMIN,
            },
        )

    return redirect("/sign-in")


@app.route("/help", methods=["GET"])
def help():
    return renderTemplate(
        "help.html",
        {
            # "csrf_form": session["csrf"],
            "email": session["email"]["email"]
            if "email" in session and "email" in session["email"]
            else "",
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
            # "csrf_form": session["csrf"],
            "email": session["email"]["email"]
            if "email" in session and "email" in session["email"]
            else "",
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
            # "csrf_form": session["csrf"],
            "email": session["email"]["email"]
            if "email" in session and "email" in session["email"]
            else "",
            "title": "Privacy Notice",
            "nav_item": "privacy-notice",
            "IS_ADMIN": IS_ADMIN,
        },
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "signed_in" in session and session["signed_in"] and "sub" in session:
        sub = session["sub"]

        user_attributes = sso_oidc.get_subs_attributes(
            sub,
            attributes=["display_name", "sms_number"],
            set_attribute_none=True,
        )

        jprint({"path": "/profile", "method": request.method}, user_attributes)

        if request.method == "POST":
            required_form_fields = ["csrf_form", "display-name", "sms-number"]
            for field in required_form_fields:
                if field not in request.form:
                    return returnError(403)

            if "csrf" not in session:
                return returnError(403)

            if session["csrf"] != request.form["csrf_form"]:
                return returnError(403)

            new_display_name = sanitise_string(request.form["display-name"])
            new_sms_number = sanitise_string(
                request.form["sms-number"],
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

        display_name = (
            user_attributes["display_name"] if "display_name" in user_attributes else ""
        )

        sms_number = (
            user_attributes["sms_number"] if "sms_number" in user_attributes else ""
        )

        session["csrf"] = random_string()
        return renderTemplate(
            "profile.html",
            {
                "csrf_form": session["csrf"],
                "email": session["email"]["email"]
                if "email" in session and "email" in session["email"]
                else "",
                "display_name": display_name,
                "sms_number": sms_number,
                "title": "Profile",
                "nav_item": "profile",
                "IS_ADMIN": IS_ADMIN,
            },
        )

    return redirect("/sign-in")


def get_remember_me_cookie_value():
    email_raw = request.cookies.get(COOKIE_NAME_REMEMBERME, "").strip('"').strip()
    if email_raw:
        email_object = email_parts(email_raw)
        if email_object:
            return email_object["email"]
    return None


def add_remember_me_cookie(email: str, response):
    if email:
        response.set_cookie(
            COOKIE_NAME_REMEMBERME,
            email,
            secure=IS_HTTPS,
            httponly=True,
            samesite="Lax",
            max_age=31536000,
        )
    return response


def remove_remember_me_cookie(response):
    response.delete_cookie(COOKIE_NAME_REMEMBERME)
    return response


def get_browser_cookie_value():
    raw_value = request.cookies.get(COOKIE_NAME_BROWSER, "").strip('"').strip()
    if raw_value and len(raw_value) == COOKIE_BROWSER_LENGTH:
        return raw_value
    return None


def set_browser_cookie(response):
    current = get_browser_cookie_value()
    if not current:
        code = random_string(length=COOKIE_BROWSER_LENGTH)
        response.set_cookie(
            COOKIE_NAME_BROWSER,
            code,
            secure=IS_HTTPS,
            httponly=True,
            samesite="Lax",
            max_age=31536000,
        )
    return response


@app.route("/sign-in", methods=["GET", "POST"])
def signin():
    browser_cookie_value = get_browser_cookie_value()

    if "signed_in" in session and session["signed_in"]:
        return set_browser_cookie(redirect("/dashboard"))

    c_ip = client_ip()

    if request.method == "POST":
        code_fail = False

        if not browser_cookie_value:
            jprint(
                {"path": "/profile", "method": request.method},
                "browser_cookie_value not found in request",
            )
            return set_browser_cookie(returnError(425))

        if "csrf_form" in request.form:
            csrf_form = request.form["csrf_form"]
            if csrf_form != session["csrf"]:
                jprint(
                    "CSRF fail",
                    {"csrf_form": csrf_form, "session['csrf']": session["csrf"]},
                )
                return returnError(403)

            if "email" in request.form:
                email = email_parts(request.form["email"])

                email_is_valid_for_sign_in = valid_email(email)
                if not email_is_valid_for_sign_in:
                    return return_sign_in(is_error=True)

                sub = sso_oidc.write_user_sub(email=email["email"])
                session["sub"] = sub
                user_attributes = sso_oidc.get_subs_attributes(
                    sub,
                    attributes=["display_name", "sms_number"],
                    set_attribute_none=True,
                )
                session["display_name"] = user_attributes["display_name"]

                user_type = "user"  # get_user_type(email)
                if user_type is not None:

                    if IS_ADMIN and user_type != "admin":
                        return returnError(403)

                    session["email"] = email

                    remember_me = False
                    if "remember_me" in request.form:
                        if request.form["remember_me"].lower() == "true":
                            remember_me = True
                    session["remember_me"] = remember_me

                    code = random_string(9, True).lower()
                    pretty_code = f"{code[:3]}-{code[3:6]}-{code[6:]}"

                    if (
                        user_attributes["sms_number"]
                        and len(user_attributes["sms_number"]) > 1
                    ):
                        session["sms_auth_required"] = True
                    else:
                        session["sms_auth_required"] = False

                    if USE_NOTIFY:
                        response = notifications_client.send_email_notification(
                            email_address=email["email"],
                            template_id=env_var("NOTIFY_EMAIL_AUTH_CODE_TEMPLATE"),
                            personalisation={
                                "auth_code": pretty_code,
                                "display_name": user_attributes["display_name"]
                                if "display_name" in user_attributes
                                and user_attributes["display_name"]
                                else session["email"]["email"],
                                "obfuscated_ip ": (
                                    ".".join(c_ip.split(".")[:-1]) + ".*"
                                )
                                if "." in c_ip
                                else (":".join(c_ip.split(":")[:-1]) + ":*")
                                if ":" in c_ip
                                else "Unknown",
                                "country": request.headers[
                                    "cloudfront-viewer-country-name"
                                ]
                                if "cloudfront-viewer-country-name" in request.headers
                                else "Unknown",
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

                    session["email-sign-in-code"] = code

                    jprint(
                        {
                            "email": session["email"]["email"]
                            if "email" in session and "email" in session["email"]
                            else "",
                            "client_ip": c_ip,
                            "action": "sign-in-request-email",
                            "pretty_code": pretty_code,
                            "browser_cookie_value": browser_cookie_value,
                        }
                    )
                else:
                    return return_sign_in(is_error=True)

            user_attributes = {}
            if "sub" in session:
                user_attributes = sso_oidc.get_subs_attributes(
                    session["sub"],
                    attributes=["display_name", "sms_number"],
                    set_attribute_none=True,
                )

            if "code" in request.form:
                code = request.form["code"].lower().replace("-", "").strip()
                code_type = request.form["code_type"]

                signed_in = False

                sms_auth_required = False
                if "sms_auth_required" in session and session["sms_auth_required"]:
                    sms_auth_required = session["sms_auth_required"]

                if code_type == "phone" and "sms-sign-in-code" in session:
                    if code.replace("-", "").strip() != session["sms-sign-in-code"]:
                        jprint(
                            {
                                "email": session["email"]["email"]
                                if "email" in session and "email" in session["email"]
                                else "",
                                "client_ip": client_ip(),
                                "action": "code-fail",
                                "browser_cookie_value": browser_cookie_value,
                            }
                        )
                        return return_sign_in(
                            is_code=True, code_type="phone", code_fail=True
                        )
                    else:
                        if (
                            "email-sign-in-complete" in session
                            and session["email-sign-in-complete"]
                        ):
                            session.pop("email-sign-in-complete")
                            session.pop("sms-sign-in-code")
                            session["mfa_quality"] = "medium"
                            signed_in = True
                        else:
                            return redirect("/sign-in")

                if code_type == "email":
                    if code != session["email-sign-in-code"]:
                        jprint(
                            json.dumps(
                                {
                                    "email": session["email"]["email"]
                                    if "email" in session
                                    and "email" in session["email"]
                                    else "",
                                    "client_ip": client_ip(),
                                    "action": "code-fail",
                                    "browser_cookie_value": browser_cookie_value,
                                },
                                default=str,
                            )
                        )
                        return return_sign_in(
                            is_code=True, code_type="email", code_fail=True
                        )
                    else:
                        session.pop("email-sign-in-code")
                        session["email-sign-in-complete"] = True
                        session["mfa_quality"] = None
                        session["pf_quality"] = "medium" # TODO, "high" if Google/Microsoft

                        if not sms_auth_required:
                            signed_in = True
                        else:
                            if (
                                "sms_number" not in user_attributes
                                or not user_attributes["sms_number"]
                            ):
                                return redirect("/sign-in")

                            code = random_string(9, only_numbers=True)
                            pretty_code = f"{code[:3]}-{code[3:6]}-{code[6:]}"

                            if USE_NOTIFY:
                                response = notifications_client.send_sms_notification(
                                    phone_number=user_attributes["sms_number"],
                                    template_id=env_var(
                                        "NOTIFY_SMS_AUTH_CODE_TEMPLATE"
                                    ),
                                    personalisation={
                                        "sms_auth_code": pretty_code,
                                        "display_name": user_attributes["display_name"]
                                        if "display_name" in user_attributes
                                        and user_attributes["display_name"]
                                        else session["email"]["email"],
                                    },
                                )

                            session["sms-sign-in-code"] = code

                            jprint(
                                {
                                    "email": session["email"]["email"]
                                    if "email" in session
                                    and "email" in session["email"]
                                    else "",
                                    "client_ip": c_ip,
                                    "action": "sign-in-request-sms",
                                    "sms_number": user_attributes["sms_number"],
                                    "pretty_code": pretty_code,
                                    "browser_cookie_value": browser_cookie_value,
                                }
                            )

                            return return_sign_in(
                                is_code=True, code_type="phone", code_fail=code_fail
                            )

                if signed_in:
                    session["signed_in"] = True

                    jprint(
                        {
                            "sub": session["sub"],
                            "email": session["email"]["email"]
                            if "email" in session and "email" in session["email"]
                            else "",
                            "client_ip": client_ip(),
                            "action": "sign-in-successful",
                            "browser_cookie_value": browser_cookie_value,
                        }
                    )

                    redirect_url = "/dashboard"

                    clients = sso_oidc.get_clients()

                    if "to_app" in request.values:
                        to_app_client_id = request.values["to_app"]
                        if to_app_client_id and to_app_client_id in clients:
                            redirect_url = "/auth/oidc"

                    if "remember_me" in session and session["remember_me"]:
                        return add_remember_me_cookie(
                            session["email"]["email"], redirect(redirect_url)
                        )
                    else:
                        return remove_remember_me_cookie(redirect(redirect_url))

        return return_sign_in(is_code=True, code_fail=code_fail)
    else:
        return return_sign_in()


def return_sign_in(
    is_error: bool = False,
    code_fail: bool = False,
    is_code: bool = False,
    code_type: str = "email",
):
    session["csrf"] = random_string()

    to_app_client_id = None
    if "to_app" in request.values:
        to_app_client_id = request.values["to_app"]
        jprint({"to_app_client_id": to_app_client_id})

    erm = get_remember_me_cookie_value()

    page_params = {
        "email_remember_me": erm,
        "csrf_form": session["csrf"],
        "is_error": is_error,
        "code_fail": code_fail,
        "title": f"{code_type.title()} Code",
        "form_url": "/sign-in",
        "code_type": code_type,
        "cancel_href": None,
    }

    clients = sso_oidc.get_clients()

    if to_app_client_id and to_app_client_id in clients:

        if "name" in clients[to_app_client_id]:
            page_params.update({"to_app_name": clients[to_app_client_id]["name"]})

        if "app_url" in clients[to_app_client_id]:
            page_params.update({"cancel_href": clients[to_app_client_id]["app_url"]})

        page_params.update({"form_url": f"/sign-in?to_app={to_app_client_id}"})

    return set_browser_cookie(
        make_response(
            renderTemplate("code.html" if is_code else "sign-in.html", page_params)
        )
    )


def returnError(status_code: int = 500):
    return make_response(
        renderTemplate(
            "error.html", {"title": "Error", "endpoint": request.full_path}, status_code
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
