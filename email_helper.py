import re


def email_parts(email: str) -> dict:
    """
    Returns the search keys from a given email address as a list (in priority order)

    >>> email_parts("")
    {}
    >>> email_parts("not.an.email.com")
    {}
    >>> email_parts("bad@single_domain")
    {}
    >>> email_parts(" @bad.com")
    {}

    >>> email_parts("good@single_domain.com")
    {'identifier': 'good', 'with_plus': 'good', 'domain': 'single_domain.com', 'email': 'good@single_domain.com', 'email_with_plus': 'good@single_domain.com'}

    >>> email_parts("good+should_be_ignored@single_domain.com")
    {'identifier': 'good', 'with_plus': 'good+should_be_ignored', 'domain': 'single_domain.com', 'email': 'good@single_domain.com', 'email_with_plus': 'good+should_be_ignored@single_domain.com'}

    >>> email_parts("good+should_also+be_ignored@single_domain.com")
    {'identifier': 'good', 'with_plus': 'good+should_alsobe_ignored', 'domain': 'single_domain.com', 'email': 'good@single_domain.com', 'email_with_plus': 'good+should_alsobe_ignored@single_domain.com'}

    >>> email_parts("Case@DoesNotMatter.com")
    {'identifier': 'case', 'with_plus': 'case', 'domain': 'doesnotmatter.com', 'email': 'case@doesnotmatter.com', 'email_with_plus': 'case@doesnotmatter.com'}

    >>> email_parts("url_encoded%40allowed-too.com")
    {'identifier': 'url_encoded', 'with_plus': 'url_encoded', 'domain': 'allowed-too.com', 'email': 'url_encoded@allowed-too.com', 'email_with_plus': 'url_encoded@allowed-too.com'}

    >>> email_parts("url_encoded%40allowed-too@this-could-be-bad.com")
    {'identifier': 'url_encoded', 'with_plus': 'url_encoded', 'domain': 'this-could-be-bad.com', 'email': 'url_encoded@this-could-be-bad.com', 'email_with_plus': 'url_encoded@this-could-be-bad.com'}
    """

    email = email.strip().lower()

    res = {}

    if email:
        x = re.search("^(?P<identifier>.*)(\@|%40)(?P<domain>.*\..*)$", email)
        if x:
            identifiers = extractIdentifiers(x.group("identifier"))
            if not identifiers:
                return res
            else:
                identifier = identifiers["identifier"]
                with_plus = identifiers["with_plus"]

            domain = x.group("domain")
            if len(domain.strip()) == 0:
                return res

            res["identifier"] = identifier
            res["with_plus"] = with_plus
            res["domain"] = domain
            res["email"] = f"{identifier}@{domain}"
            res["email_with_plus"] = f"{with_plus}@{domain}"

    return res


def extractIdentifiers(identifier: str) -> dict:
    identifier = identifier.strip()

    re_match = re.search("^(?P<r>.*?)(?P<a>\+.*?)?(\%|\@|$)", identifier).groupdict()
    res = re_match["r"]
    add = re_match["a"]

    if res:
        res = res.strip()

        if add:
            add = add.replace("+", "").replace("%", "").replace("@", "").strip()
            return {"identifier": res, "with_plus": f"{res}+{add}"}

        return {"identifier": res, "with_plus": res}

    return {}


def emailKeys(email: str) -> list:
    """
    Returns the search keys from a given email address as a list (in priority order)

    >>> emailKeys("")
    []
    >>> emailKeys("not.an.email.com")
    []
    >>> emailKeys("bad@single_domain")
    []
    >>> emailKeys("bad@bad.....com")
    []
    >>> emailKeys(" @bad.com")
    []

    >>> emailKeys("good@single_domain.com")
    ['email:good@single_domain.com', 'domain:single_domain.com']

    >>> emailKeys("url_encoded%40allowed-too.com")
    ['email:url_encoded@allowed-too.com', 'domain:allowed-too.com']

    >>> r = emailKeys("firstname.lastname+magiclink@test.service.gov.uk")
    >>> e = ['email:firstname.lastname+magiclink@test.service.gov.uk', \
        'email:firstname.lastname@test.service.gov.uk', \
        'domain:test.service.gov.uk', 'domain:service.gov.uk', 'domain:gov.uk']
    >>> r == e
    True

    >>> r = emailKeys("firstname.lastname@test.service.gov.uk")
    >>> e = ['email:firstname.lastname@test.service.gov.uk', \
        'domain:test.service.gov.uk', 'domain:service.gov.uk', 'domain:gov.uk']
    >>> r == e
    True

    >>> r = emailKeys("good@abc.abc.abc.com")
    >>> e = ['email:good@abc.abc.abc.com', 'domain:abc.abc.abc.com', \
        'domain:abc.abc.com', 'domain:abc.com']
    >>> r == e
    True
    """

    res = []

    email_parts = email_parts(email)
    if email_parts:
        domain = email_parts["domain"]

        if email_parts["email_with_plus"] != email_parts["email"]:
            # add the full email with plus, e.g: firstname.lastname+example@test.service.gov.uk
            res.append(f"email:{email_parts['email_with_plus']}")

        # add the normalised email, e.g: firstname.lastname@test.service.gov.uk
        res.append(f"email:{email_parts['email']}")

        # add the full domain, e.g: test.service.gov.uk
        res.append(f"domain:{domain}")

        # split the full domain, iterate through each except the last 2 objects
        # e.g. for test.service.gov.uk this would add the following to res list:
        # - domain:service.gov.uk
        # - domain:gov.uk
        splitDomain = domain.split(".")
        if len(splitDomain) >= 2:
            for i in splitDomain[:-2]:

                # if i has no value, e.g. bad@test...com then return empty list
                if len(i) == 0:
                    return []

                # cut the domain up by this i (the sub domain)
                domain = domain[(len(i) + 1) :]
                res.append(f"domain:{domain}")
        else:
            # if there's only one entry, e.g. for email bad@example
            # then something has gone wrong, return an empty list
            return []

    return res


if __name__ == "__main__":
    """
    If this python is called directly, test using doctest
    """
    import doctest

    doctest.testmod()
