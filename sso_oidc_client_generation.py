import uuid
import json
import re

from sso_utils import random_string


def generate_client_auth_pair():
    """
    Returns a valid client ID and secret

    >>> gc = generate_client_auth_pair()
    >>> "client_id" in gc
    True
    >>> len(gc["client_id"])
    36
    >>> "client_secret" in gc
    True
    >>> len(gc["client_secret"])
    64
    """
    client_id = str(uuid.uuid4())

    if not re.match(r"^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$", client_id):
        raise Exception("Unexpected client_id format!")

    cspf = "ssosecgovuk"
    cs1_len = 21
    cs1 = random_string(length=cs1_len)
    cs2_len = 30
    cs2 = random_string(length=cs2_len)
    client_secret = f"{cspf}-{cs1}-{cs2}"

    if not re.match(
        rf"^{cspf}\-[A-Za-z0-9]{{{cs1_len}}}\-[A-Za-z0-9]{{{cs2_len}}}$", client_secret
    ):
        raise Exception("Unexpected client_secret format!")

    return {"client_id": client_id, "client_secret": client_secret}


if __name__ == "__main__":
    import doctest

    flags = doctest.REPORT_NDIFF | doctest.FAIL_FAST
    fail, total = doctest.testmod(optionflags=flags)

    if not fail:
        print(json.dumps(generate_client_auth_pair(), default=str, indent=2))
