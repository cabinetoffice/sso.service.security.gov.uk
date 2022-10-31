import os
import json
import urllib.request
import urllib.parse
import re
import jwt
import traceback
import requests
import hashlib

from jwt import PyJWKClient


def random_sha256() -> str:
    return hashlib.sha256(os.urandom(1024)).hexdigest()


class GoogleAuth:
    discovery_document_url = os.getenv(
        "GOOGLE_DISCOVERY_DOCUMENT_URL",
        "https://accounts.google.com/.well-known/openid-configuration",
    )

    dev_mode = False
    _client_id = None
    _client_secret = None

    def set_creds(self, client_id: str = None, client_secret: str = None):
        if not client_id and not client_secret:
            self._client_id = os.getenv("GOOGLE_CLIENT_ID")
            self._client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        else:
            self._client_id = client_id
            self._client_secret = client_secret

        if not self._client_id or not self._client_secret:
            raise Exception("Arguments client_id or client_secret not set")

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        use_override_env_var: bool = True,
        dev_mode: bool = False,
    ):
        self.set_creds(client_id, client_secret)
        self.reset(use_override_env_var, dev_mode)

    def reset(self, use_override_env_var: bool = True, dev_mode: bool = False):
        self._google_oidc_config = {}

        self._google_fetch_is_error = False
        self._google_fetch_error_msg = None

        self.issuer = None
        self.auth_endpoint = None
        self.token_endpoint = None
        self.jwks_uri = None

        self.scopes = ["openid", "email", "profile"]

        self._init_config(oev=use_override_env_var)

    def get_oidc_config(self) -> dict:
        if not self._google_fetch_is_error and not self._google_oidc_config:
            try:
                with urllib.request.urlopen(
                    self.discovery_document_url, timeout=3
                ) as url:
                    if url:
                        data = json.load(url)
                        if (
                            data
                            and "issuer" in data
                            and self.discovery_document_url.startswith(data["issuer"])
                        ):
                            self._google_oidc_config = data
            except Exception as e:
                self._google_fetch_error_msg = str(e) + traceback.format_exc()
                self._google_fetch_is_error = True

        return self._google_oidc_config

    def _init_config(self, oev=True):
        if oev:
            self.issuer = os.getenv("GOOGLE_ISSUER")
            self.auth_endpoint = os.getenv("GOOGLE_AUTH_ENDPOINT")
            self.token_endpoint = os.getenv("GOOGLE_TOKEN_ENDPOINT")
            self.jwks_uri = os.getenv("GOOGLE_JWKS_URI")

        if not self.issuer:
            self.issuer = self.get_oidc_config().get("issuer")
        if not self.auth_endpoint:
            self.auth_endpoint = self.get_oidc_config().get("authorization_endpoint")
        if not self.token_endpoint:
            self.token_endpoint = self.get_oidc_config().get("token_endpoint")
        if not self.jwks_uri:
            self.jwks_uri = self.get_oidc_config().get("jwks_uri")

    def is_ready(self) -> bool:
        starts = f"http{'s://' if not self.dev_mode else ''}"
        return 3 == [
            starts
            for x in [self.auth_endpoint, self.token_endpoint, self.jwks_uri]
            if x and type(x) == str and x.startswith(starts)
        ].count(starts)

    def get_error(self) -> tuple:
        if self.is_ready():
            return (False, None)
        if self._google_fetch_is_error:
            res = (True, self._google_fetch_error_msg)
        else:
            res = (True, "Incomplete or invalid parameters")
        return res

    def step_one_get_redirect_url(
        self,
        callback_url: str = None,
        login_hint: str = None,
        hd_domain_hint: str = None,
        include_nonce: bool = True,
        override_nonce: str = None,
        override_state: str = None,
        override_prompt: str = None,
        override_response_type: str = None,
    ) -> str:
        if not self.is_ready():
            return {"error": True, "error_message": "Not configured"}

        if not callback_url:
            return {"error": True, "error_message": "Argument callback_url not set"}
        elif "%" not in callback_url or "&" in callback_url:
            callback_url = urllib.parse.quote(callback_url)

        response_type = override_response_type if override_response_type else "code"
        scope_string = urllib.parse.quote(" ".join(self.scopes))

        state = override_state if override_state else random_sha256()
        nonce = (
            override_nonce
            if override_nonce
            else (random_sha256() if include_nonce else None)
        )

        prompt = override_prompt if override_prompt else "consent"

        url = f"""{self.auth_endpoint}?
        response_type={response_type}&
        client_id={self._client_id}&
        scope={scope_string}&
        redirect_uri={callback_url}&
        state={state}&
        {f'nonce={nonce}&' if nonce else ''}
        {f'login_hint={login_hint}&' if login_hint else ''}
        {f'prompt={prompt}&' if prompt else ''}
        {f'hd={hd_domain_hint}&' if hd_domain_hint else ''}"""

        url = re.sub(r"\s", "", url).strip("&")
        return {
            "error": False,
            "error_message": None,
            "url": url,
            "state": state,
            "nonce": nonce,
        }

    def step_two_get_id_token_from_google_url(
        self,
        url: str = None,
        state_to_compare: str = None,
        redirect_uri: str = None,
    ) -> dict:
        if not url:
            return {"error": True, "error_message": "Argument 'url' not set or empty"}

        parsed_url = None
        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception as e:
            return {"error": True, "error_message": str(e) + traceback.format_exc()}
        if not parsed_url:
            return {"error": True, "error_message": "URL parsing issue"}

        params = {}
        querystrings = {}
        fragments = {}

        if parsed_url.query:
            querystrings = urllib.parse.parse_qs(parsed_url.query)
            if querystrings:
                params.update(
                    {
                        qx: ",".join(querystrings[qx])
                        if type(querystrings[qx]) == list
                        else str(querystrings[qx])
                        for qx in querystrings
                    }
                )

        if parsed_url.fragment:
            fragments = urllib.parse.parse_qs(parsed_url.fragment)
            if fragments:
                params.update(
                    {
                        fx: ",".join(fragments[fx])
                        if type(fragments[fx]) == list
                        else str(fragments[fx])
                        for fx in fragments
                    }
                )

        if params.get("error") or params.get("error_subtype"):
            em = [
                "Google error response",
                "querystring" if querystrings else "fragment",
                params.get("error_subtype"),
                params.get("error"),
            ]
            return {"error": True, "error_message": ": ".join(filter(None, em))}

        returned_state = params.get("state")
        if state_to_compare or returned_state:
            if state_to_compare != returned_state:
                return {"error": True, "error_message": "state mismatch"}

        returned_hd = params.get("hd")
        returned_id_token = params.get("id_token")
        returned_code = params.get("code")

        validated_id_token = None

        if not returned_code and not returned_id_token:
            return {
                "error": True,
                "error_message": "missing code or id_token in Google's response",
            }
        elif returned_code and not returned_id_token:
            err, s3res = self.get_id_token_from_auth_code(returned_code, redirect_uri)
            if err:
                return {"error": True, "error_message": s3res}
            else:
                returned_id_token = s3res.get("id_token")

        if returned_id_token:
            err, s4res = self.verify_and_decode_id_token(returned_id_token)
            if err:
                return {
                    "error": True,
                    "error_message": s4res,
                }
            else:
                validated_id_token = s4res

        if validated_id_token:
            return {
                "error": False,
                "error_message": None,
                "id_token": validated_id_token,
            }

        return {"error": True, "error_message": None}

    def get_id_token_from_auth_code(
        self,
        code: str = None,
        redirect_uri: str = None,
    ):
        # return tuple containing if error and result
        # (True == error | False == no error, data)

        http_resp = None
        data = {}

        try:
            head = {"Content-Type": "application/x-www-form-urlencoded"}
            body = {
                "code": code,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "authorization_code",
            }
            if redirect_uri:
                body["redirect_uri"] = redirect_uri

            http_resp = requests.post(self.token_endpoint, body, head)
            data = (
                http_resp.json()
                if http_resp.text and http_resp.text.startswith("{")
                else {}
            )
            if data and "error" in data:
                raise Exception(
                    f"Google token_endpoint ({self.token_endpoint}) response: {data}"
                )
        except Exception as e:
            return (True, e)

        if data:
            return (False, data)

        return (True, None)

    def verify_and_decode_id_token(self, id_token: str = None) -> tuple:
        # return tuple containing if error and result
        # (True == error | False == no error, data)

        data = {}

        try:
            jwks_client = PyJWKClient(self.jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
            data = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._client_id,
                options={"verify_exp": True},
            )
        except Exception as e:
            return (True, str(e) + traceback.format_exc())

        return (data.get("iss") is None, data)
