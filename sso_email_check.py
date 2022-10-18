from sso_utils import env_var, to_list
from email_helper import email_parts


def valid_email(email_input, client: dict = {}) -> bool:
    email_object = {}

    if type(email_input) == dict and "email" in email_input and "domain" in email_input:
        email_object = email_input
    elif type(email_input) == str:
        email_object = email_parts(email_input)

    if not email_object:
        return False

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

    # Blocked / negative checks

    if blocked_emails:
        if email in blocked_emails:
            return False

    if blocked_domains:
        if domain in blocked_domains:
            return False
        for domain_to_check in blocked_domains:
            if "*" in domain_to_check and domain.endswith(domain_to_check.strip("*")):
                return False

    # Allowed / positive checks

    if allowed_emails:
        if email in allowed_emails:
            return True

    if allowed_domains:
        if domain in allowed_domains:
            return True
        for domain_to_check in allowed_domains:
            if "*" in domain_to_check and domain.endswith(domain_to_check.strip("*")):
                return True

    return False
