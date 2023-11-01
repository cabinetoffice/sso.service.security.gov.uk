import json
import re
import dns.resolver

from sso_utils import env_var, to_list
from email_helper import email_parts

ENVIRONMENT = env_var("ENVIRONMENT", "development")
IS_PROD = ENVIRONMENT.lower().startswith("prod")
DEBUG = not IS_PROD

resolver = None
resolver_set = False
resolver_location = env_var("DNS_RESOLVER", "dns.google")

unexpected_source_re = re.compile(
    r"from \([\"'](?P<ip>[\[\]\:\.0-9a-fA-F]+)[\"'],\s*(?P<port>\d+)"
)


def get_resolver(depth: int = 0):
    global resolver
    global resolver_set
    global resolver_location

    if not resolver_set:
        try:
            resolver = dns.resolver.make_resolver_at(resolver_location)
            resolver.resolve("digital.cabinet-office.gov.uk", "MX", lifetime=6)
            resolver_set = True
        except Exception as e:
            if depth > 1:
                raise e
            if e and "kwargs" in dir(e):
                for x in e.kwargs.get("errors", {}):
                    if len(x) > 4 and isinstance(x[3], dns.query.UnexpectedSource):
                        new_from = unexpected_source_re.search(str(x[3]))
                        if new_from:
                            resolver_location = new_from.group(1)
                            resolver = get_resolver(depth=(depth + 1))
                            break
    return resolver


def get_dns_records(domain_name: str, qtype: str) -> list:
    res = []
    try:
        answers = get_resolver().resolve(domain_name, qtype)
        for rr in answers:
            if rr:
                res.append(rr.to_text().strip('"'))
    except Exception as e:
        pass
    return res


def get_mx_records(domain_name: str) -> list:
    return get_dns_records(domain_name, "MX")


def valid_email(email_input, client: dict = {}, debug: bool = False) -> dict:
    res = {"valid": False, "auth_type": None, "user_type": None}
    email_object = {}

    if type(email_input) == dict and "email" in email_input and "domain" in email_input:
        email_object = email_input
    elif type(email_input) == str:
        email_object = email_parts(email_input)

    if not email_object:
        if debug:
            print(
                json.dumps(
                    {
                        "sso_email_check": {
                            "message": "No email object",
                            "email_input": email_input,
                        }
                    },
                    default=str,
                )
            )
        return res

    email = email_object["email"]
    domain = email_object["domain"]

    blocked_emails = []
    blocked_domains = []
    allowed_emails = []
    allowed_domains = []

    if client:
        blocked_emails = client["blocked_emails"] if "blocked_emails" in client else []
        blocked_domains = (
            client["blocked_domains"] if "blocked_domains" in client else []
        )

        allowed_emails = client["allowed_emails"] if "allowed_emails" in client else []
        allowed_domains = (
            client["allowed_domains"] if "allowed_domains" in client else []
        )
    else:
        blocked_emails = to_list(env_var("SIGN_IN_EMAILS_BLOCKED"))
        blocked_domains = to_list(env_var("SIGN_IN_DOMAINS_BLOCKED"))

        allowed_emails = to_list(env_var("SIGN_IN_EMAILS_ALLOWED"))
        allowed_domains = to_list(env_var("SIGN_IN_DOMAINS_ALLOWED"))

    if debug:
        print(
            json.dumps(
                {
                    "sso_email_check": {
                        "email": email,
                        "domain": domain,
                        "blocked_emails": blocked_emails,
                        "blocked_domains": blocked_domains,
                        "allowed_emails": allowed_emails,
                        "allowed_domains": allowed_domains,
                    }
                },
                default=str,
            )
        )

    # Blocked / negative checks

    if blocked_emails:
        if email in blocked_emails:
            return res

    if blocked_domains:
        if domain in blocked_domains:
            return res
        else:
            for domain_to_check in blocked_domains:
                if "*" in domain_to_check:
                    if domain.endswith(domain_to_check.strip("*")):
                        return res
                    elif domain == domain_to_check.strip("*").strip("."):
                        return res
                elif domain.endswith(f".{domain_to_check}"):
                    return res

    # Allowed / positive checks

    if allowed_emails:
        if email in allowed_emails:
            res["valid"] = True

    if allowed_domains:
        if domain in allowed_domains:
            res["valid"] = True
        else:
            for domain_to_check in allowed_domains:
                if "*" in domain_to_check:
                    if domain.endswith(domain_to_check.strip("*")):
                        res["valid"] = True
                    elif domain == domain_to_check.strip("*").strip("."):
                        res["valid"] = True
                elif domain.endswith(f".{domain_to_check}"):
                    res["valid"] = True

    if res["valid"]:
        res["auth_type"] = get_auth_type(email)
        res["user_type"] = get_user_type(email)

    return res


def get_auth_type(email) -> str:
    if not IS_PROD:
        domain = email.split("@", 1)[1]
        mx_records = get_mx_records(domain)
        uses_ms = False
        uses_g = False
        for mx in mx_records:
            mx = mx.strip(".")
            if mx.endswith(".outlook.com"):
                uses_ms = True
                break
            if mx.endswith(".google.com") or mx.endswith(".googlemail.com"):
                uses_g = True
                break

        print(
            "sso_email_check:get_auth_type:domain:",
            domain,
            "uses_ms:",
            uses_ms,
            "uses_g:",
            uses_g,
        )

        if uses_ms:
            return "microsoft"
        if uses_g:
            return "google"

    if email.endswith("@digital.cabinet-office.gov.uk"):
        return "google"

    if email.endswith("@cabinetoffice.gov.uk"):
        return "google"

    return "email"


def get_user_type(email) -> str:
    return "user"
