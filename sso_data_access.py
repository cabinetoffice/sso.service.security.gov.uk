import os
import boto3

from time import sleep

from sso_utils import env_var, jprint

USE_AWS_S3_SESSIONS = env_var("USE_AWS_S3_SESSIONS", "f", return_bool=True)
AWS_SESSION_BUCKET = env_var("AWS_SESSION_BUCKET")
AWS_CLIENT_BUCKET = env_var("AWS_CLIENT_BUCKET")
TMP_PATH = ".runtime"


s3_client = None


def get_s3_client():
    global s3_client
    if not s3_client:
        s3_client = boto3.client("s3")
    return s3_client


def init_data_layer():
    if USE_AWS_S3_SESSIONS:
        # check access
        sess_response = get_s3_client().get_bucket_acl(Bucket=AWS_SESSION_BUCKET)
        sess_status = (
            sess_response["ResponseMetadata"]["HTTPStatusCode"]
            if sess_response
            and "ResponseMetadata" in sess_response
            and "HTTPStatusCode" in sess_response["ResponseMetadata"]
            else -1
        )

        clie_response = get_s3_client().get_bucket_acl(Bucket=AWS_CLIENT_BUCKET)
        clie_status = (
            clie_response["ResponseMetadata"]["HTTPStatusCode"]
            if clie_response
            and "ResponseMetadata" in clie_response
            and "HTTPStatusCode" in clie_response["ResponseMetadata"]
            else -1
        )

        jprint(
            {
                "init_data_layer": {
                    "AWS_SESSION_BUCKET": {
                        "Name": AWS_SESSION_BUCKET,
                        "Status": sess_status,
                    },
                    "AWS_CLIENT_BUCKET": {
                        "Name": AWS_CLIENT_BUCKET,
                        "Status": clie_status,
                    },
                }
            }
        )
    else:
        if not os.path.exists(TMP_PATH):
            os.makedirs(TMP_PATH)

        clients = os.path.join(TMP_PATH, "clients")
        if not os.path.exists(clients):
            os.makedirs(clients)

        subs = os.path.join(TMP_PATH, "subs")
        if not os.path.exists(subs):
            os.makedirs(subs)

        subs_gmail = os.path.join(TMP_PATH, "subs", "gmail")
        if not os.path.exists(subs_gmail):
            os.makedirs(subs_gmail)

        subs_microsoft = os.path.join(TMP_PATH, "subs", "microsoft")
        if not os.path.exists(subs_microsoft):
            os.makedirs(subs_microsoft)

        subs_email = os.path.join(TMP_PATH, "subs", "email")
        if not os.path.exists(subs_email):
            os.makedirs(subs_email)

        subs_sub = os.path.join(TMP_PATH, "subs", "sub")
        if not os.path.exists(subs_sub):
            os.makedirs(subs_sub)

        auth_codes = os.path.join(TMP_PATH, "auth_codes")
        if not os.path.exists(auth_codes):
            os.makedirs(auth_codes)

        access_codes = os.path.join(TMP_PATH, "access_codes")
        if not os.path.exists(access_codes):
            os.makedirs(access_codes)

        jprint({"init_data_layer": {"local": True}})


init_data_layer()


def get_bucket(bt: str = None):
    res = None

    if bt == "sessions" or bt.endswith("sessions"):
        res = AWS_SESSION_BUCKET

    if bt == "clients" or bt.endswith("clients"):
        res = AWS_CLIENT_BUCKET

    return res


def delete_file(filename: str, bucket_type: str = "sessions") -> bool:
    res = False
    if USE_AWS_S3_SESSIONS:
        try:
            get_s3_client().delete_object(Bucket=get_bucket(bucket_type), Key=filename)
            res = True
        except Exception as e:
            jprint({"function": "delete_file", "error": str(e)})
    else:
        fn = os.path.join(TMP_PATH, os.path.normpath(filename))
        if os.path.exists(fn):
            os.remove(fn)
            res = True
    return res


def read_all_files(
    folder: str = "", default: str = None, bucket_type: str = "sessions"
) -> list:
    res = []
    keys = []

    if USE_AWS_S3_SESSIONS:
        try:
            s3_res = get_s3_client().list_objects_v2(
                Bucket=get_bucket(bucket_type), Prefix=folder
            )
            if "Contents" in s3_res:
                for key in s3_res["Contents"]:
                    keys.append(key["Key"])
        except Exception as e:
            jprint({"function": "read_all_files", "error": str(e)})
    else:
        for filename in os.listdir(
            os.path.join(
                os.path.join(TMP_PATH, "clients")
                if bucket_type == "clients"
                else TMP_PATH,
                os.path.normpath(folder),
            )
        ):
            keys.append(os.path.join(folder, filename))

    for key in keys:
        fres = read_file(key, default, bucket_type)
        if fres:
            res.append(fres)

    return res


def read_file(filename: str, default: str = None, bucket_type: str = "sessions") -> str:
    res = default

    # jprint(
    #    {
    #        "function": "read_file",
    #        "message": f"Attempting to read '{filename}'",
    #        "USE_AWS_S3_SESSIONS": USE_AWS_S3_SESSIONS,
    #        "bucket": get_bucket(bucket_type),
    #    }
    # )

    if USE_AWS_S3_SESSIONS:
        try:
            s3_object = get_s3_client().get_object(
                Bucket=get_bucket(bucket_type), Key=filename
            )
            if "Body" in s3_object:
                body = s3_object["Body"]
                res = body.read()
            else:
                raise Exception("Missing 'Body' in s3_object")
        except Exception as e:
            jprint({"function": "read_file", "error": str(e)})
    else:
        fn = os.path.join(
            os.path.join(TMP_PATH, "clients") if bucket_type == "clients" else TMP_PATH,
            os.path.normpath(filename),
        )
        if os.path.isfile(fn):
            f = open(fn, "r")
            res = f.read()

    if type(res) == bytes:
        res = res.decode("utf-8").strip()
    return res


def write_file(filename: str, content: str = "", bucket_type: str = "sessions") -> bool:
    res = False

    if ".." in filename:
        return res

    if USE_AWS_S3_SESSIONS:
        try:
            get_s3_client().put_object(
                Body=content.encode("utf-8"),
                Bucket=get_bucket(bucket_type),
                Key=filename,
            )
            res = True
            sleep(0.1)
        except Exception as e:
            jprint({"function": "write_file", "error": str(e)})
    else:
        try:
            fn = os.path.join(
                os.path.join(TMP_PATH, "clients")
                if bucket_type == "clients"
                else TMP_PATH,
                os.path.normpath(filename),
            )
            f = open(fn, "w")
            f.write(content)
            f.close()
            res = True
        except Exception as e:
            print(e)

    return res
