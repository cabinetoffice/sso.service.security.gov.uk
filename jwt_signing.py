import boto3
import base64
import json

from sso_utils import env_var


TEST_RSA_JSON_OBJECT = {}
RAW_TEST_RSA_JSON_OBJECT = env_var("TEST_RSA_JSON_OBJECT", "").strip("'")
if RAW_TEST_RSA_JSON_OBJECT and RAW_TEST_RSA_JSON_OBJECT.startswith("{"):
    TEST_RSA_JSON_OBJECT = json.loads(RAW_TEST_RSA_JSON_OBJECT)

CURRENT_SIGNING_KID = env_var("CURRENT_SIGNING_KID")
USE_AWS_KMS = env_var("USE_AWS_KMS", "f", return_bool=True)
AWS_REGION = env_var("AWS_REGION")

g_jwks_doc = []


def get_jwks():
    global g_jwks_doc
    if not g_jwks_doc:
        from authlib.jose import JsonWebKey

        public_keys = get_public_keys()
        for kid in public_keys:
            jda = JsonWebKey.import_key(public_keys[kid], {"kty": "RSA"}).as_dict()
            jda.update({"alg": "RSA256", "use": "sig", "kid": kid})
            g_jwks_doc.append(jda)
    return {"keys": g_jwks_doc}


def get_public_keys():
    res = {CURRENT_SIGNING_KID: None}
    if USE_AWS_KMS:
        client = boto3.client("kms", region_name=AWS_REGION)
        response = client.get_public_key(KeyId=CURRENT_SIGNING_KID)
        if "PublicKey" in response:
            pkb64bytes = base64.b64encode(response["PublicKey"])
            pkb64str = pkb64bytes.decode("ascii")
            res[
                CURRENT_SIGNING_KID
            ] = f"-----BEGIN PUBLIC KEY-----\n{pkb64str}\n-----END PUBLIC KEY-----"
    elif TEST_RSA_JSON_OBJECT:
        if CURRENT_SIGNING_KID in TEST_RSA_JSON_OBJECT:
            res[CURRENT_SIGNING_KID] = TEST_RSA_JSON_OBJECT[CURRENT_SIGNING_KID][
                "public_key"
            ]
    return res


def get_private_keys():
    res = {CURRENT_SIGNING_KID: None}
    if USE_AWS_KMS:
        # not applicable for KMS
        raise Exception(
            "Cannot get private keys when using AWS KMS, this function is for local testing only"
        )
    elif TEST_RSA_JSON_OBJECT:
        if CURRENT_SIGNING_KID in TEST_RSA_JSON_OBJECT:
            res[CURRENT_SIGNING_KID] = TEST_RSA_JSON_OBJECT[CURRENT_SIGNING_KID][
                "private_key"
            ]
    return res


def jwt_safe_b64(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode("utf-8").replace("=", "")


def sign(payload: dict, kid: str, sigtype: str = "RSA", bits: int = 256) -> str:
    if not payload:
        return None

    if sigtype == "RSA":
        SigningAlgorithm = f"RSASSA_PKCS1_V1_5_SHA_{bits}"
        alg = f"RS{bits}"

    header = {
        "typ": "JWT",
        "alg": alg,
        "kid": kid,
    }

    header_base64 = jwt_safe_b64(str.encode(json.dumps(header)))
    payload_base64 = jwt_safe_b64(str.encode(json.dumps(payload)))

    jwt = f"{header_base64}.{payload_base64}"

    response = {}

    if USE_AWS_KMS:  # AWS KMS
        client = boto3.client("kms", region_name=AWS_REGION)
        response = client.sign(
            KeyId=kid,
            Message=jwt,
            MessageType="RAW",
            SigningAlgorithm=SigningAlgorithm,
        )
    else:
        from Crypto.PublicKey import RSA
        from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
        from Crypto.Hash import SHA256

        hash = SHA256.new(jwt.encode("utf-8"))
        pks = get_private_keys()
        if kid in pks:
            keypair = RSA.import_key(pks[kid])
            signer = PKCS115_SigScheme(keypair)
            response["Signature"] = signer.sign(hash)

    if "Signature" in response:
        sig = (
            base64.urlsafe_b64encode(response["Signature"])
            .decode("utf-8")
            .replace("=", "")
        )

        sig = jwt_safe_b64(response["Signature"])

        return f"{jwt}.{sig}"

    return None
