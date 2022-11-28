import json

from sso_utils import env_var, to_list
from email_helper import email_parts


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
    # if email.endswith("oliver.chalk@digital.cabinet-office.gov.uk"):
    #    return "microsoft"
    # if email.endswith("@cabinetoffice.gov.uk"):
    #    return "google"
    if email.endswith("@digital.cabinet-office.gov.uk"):
        return "google"
    return "email"


def get_user_type(email) -> str:
    return "user"
