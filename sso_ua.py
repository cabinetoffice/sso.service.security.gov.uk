import re

browsers = {
    "Firefox": "Firefox",
    "FxiOS": "Firefox",
    "Edg": "Edge",
    "EdgA": "Edge",
    "EdgiOS": "Edge",
    "OPR": "Opera",
    "Vivaldi": "Vivaldi",
    "CriOS": "Chrome",
    "Chrome": "Chrome",
    "Safari": "Safari",
}
browsers_regex = re.compile(rf"({'|'.join(browsers)})\/")


def guess_browser(ua):
    res = "Unknown"

    if not ua:
        return res

    ua_matches = browsers_regex.findall(ua)
    for b in browsers:
        if b in ua_matches:
            res = browsers[b]
            break

    return res
