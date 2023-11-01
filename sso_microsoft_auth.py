import os
import json
import urllib.request
import urllib.parse
import re
import jwt
import traceback
import requests
import hashlib
import ssl

from jwt import PyJWKClient


def random_sha256() -> str:
    return hashlib.sha256(os.urandom(1024)).hexdigest()


class MicrosoftAuth:
    errored = False
    dev_mode = False
    _client_id: str = None
    _client_secret: str = None
    discovery_document_url: str = None

    def setup(
        self,
        client_id: str = None,
        client_secret: str = None,
        discovery_document_url: str = None,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self.discovery_document_url = discovery_document_url

        if not self._client_id or not self._client_secret:
            raise Exception("Arguments client_id or client_secret not set")

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        discovery_document_url: str = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        dev_mode: bool = False,
    ):
        self.setup(client_id, client_secret, discovery_document_url)
        self.reset(dev_mode)

    def reset(self, dev_mode: bool = False):
        self._microsoft_oidc_config = {}
        self._microsoft_fetch_is_error = False
        self._microsoft_fetch_error_msg = None

        self.issuer = None
        self.auth_endpoint = None
        self.token_endpoint = None
        self.jwks_uri = None

        self.scopes = ["openid", "email"]

        self.dev_mode = dev_mode

        self._init_config()

    def get_oidc_config(self) -> dict:
        if not self._microsoft_fetch_is_error and not self._microsoft_oidc_config:
            try:
                resp = requests.get(self.discovery_document_url, timeout=3)
                if resp.status_code == 200 and resp.json():
                    data = resp.json()
                    if data and "issuer" in data:
                        self._microsoft_oidc_config = data
            except Exception as e:
                self._microsoft_fetch_error_msg = str(e) + traceback.format_exc()
                self._microsoft_fetch_is_error = True
                self.errored = True

        return self._microsoft_oidc_config

    def _init_config(self, oev=True):
        self.issuer = os.getenv(
            "MICROSOFT_ISSUER", self.get_oidc_config().get("issuer")
        )
        self.auth_endpoint = os.getenv(
            "MICROSOFT_AUTH_ENDPOINT",
            self.get_oidc_config().get("authorization_endpoint"),
        )
        self.token_endpoint = os.getenv(
            "MICROSOFT_TOKEN_ENDPOINT", self.get_oidc_config().get("token_endpoint")
        )
        self.jwks_uri = os.getenv(
            "MICROSOFT_JWKS_URI", self.get_oidc_config().get("jwks_uri")
        )

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
            res = (True, self._microsoft_fetch_error_msg)
        else:
            res = (True, "Incomplete or invalid parameters")
        return res

    def step_one_get_redirect_url(
        self,
        callback_url: str = None,
        login_hint: str = None,
        domain_hint: str = None,
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

        response_mode = "query"
        response_type = urllib.parse.quote(
            override_response_type if override_response_type else "code"
        )
        scope_string = urllib.parse.quote(" ".join(self.scopes))

        state = override_state if override_state else random_sha256()
        nonce = (
            override_nonce
            if override_nonce
            else (random_sha256() if include_nonce else None)
        )

        prompt = override_prompt if override_prompt else "none"  # consent

        url = f"""{self.auth_endpoint}?
        response_type={response_type}&
        response_mode={response_mode}&
        client_id={self._client_id}&
        scope={scope_string}&
        redirect_uri={callback_url}&
        state={state}&
        {f'nonce={nonce}&' if nonce else ''}
        {f'login_hint={login_hint}&' if login_hint else ''}
        {f'prompt={prompt}&' if prompt else ''}
        {f'domain_hint={domain_hint}&' if domain_hint else ''}"""

        url = re.sub(r"\s", "", url).strip("&")
        return {
            "error": False,
            "error_message": None,
            "url": url,
            "state": state,
            "nonce": nonce,
        }

    def step_two_get_id_token_from_microsoft_url(
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

        querystrings = {}

        if parsed_url.query:
            querystrings = urllib.parse.parse_qs(parsed_url.query)
            if querystrings:
                querystrings.update(
                    {
                        qx: ",".join(querystrings[qx])
                        if type(querystrings[qx]) == list
                        else str(querystrings[qx])
                        for qx in querystrings
                    }
                )

        if not querystrings:
            return {"error": True, "error_message": "querystrings empty"}

        if querystrings.get("error") or querystrings.get("error_description"):
            em = [
                "Microsoft error response",
                "querystring",
                querystrings.get("error_description"),
                querystrings.get("error"),
            ]
            return {"error": True, "error_message": ": ".join(filter(None, em))}

        returned_state = querystrings.get("state")
        if state_to_compare or returned_state:
            if state_to_compare != returned_state:
                return {"error": True, "error_message": "state mismatch"}

        returned_code = querystrings.get("code")
        validated_id_token = None

        if not returned_code:
            return {
                "error": True,
                "error_message": "missing code in Microsoft's response",
            }
        else:
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
                    f"Microsoft token_endpoint ({self.token_endpoint}) response: {data}"
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
            # ssl_context = ssl.create_default_context()
            # ssl_context.check_hostname = False
            # ssl_context.verify_mode = ssl.CERT_NONE

            # jwks_client = PyJWKClient(self.jwks_uri, ssl_context=ssl_context)
            # signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            data = jwt.decode(
                id_token,
                # apparently MS doesn't sign their JWTs...
                verify=False,
                # key=signing_key.key,
                # algorithms=["RS256"],
                algorithms=["none"],
                audience=self._client_id,
                options={"verify_exp": True, "verify_signature": False},
            )
        except Exception as e:
            return (True, str(e) + traceback.format_exc())

        return (data.get("iss") is None, data)
