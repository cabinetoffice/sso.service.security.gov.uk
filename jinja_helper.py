import jinja2
import colorsys
import os
import json
import hashlib
import shutil
import glob

from datetime import datetime, timezone
from sso_utils import env_var

MAIN_CSS_HASH = env_var("MAIN_CSS_HASH", None)


def colourFromLetter(letter: str = ""):
    if not letter:
        num = random.randint(65, 90)
    elif len(letter) > 1:
        letter = letter[0]
    if letter:
        num = ord(letter.upper())

    perc = (num - 61) / 30
    hexval = colorsys.hsv_to_rgb(perc, 34 / 100, 39 / 100)
    return "".join("%02X" % round(i * 255) for i in hexval)


def datetimeFromEpoch(epoch: float = 0):
    try:
        if type(epoch) == str:
            epoch = float(epoch)
        if epoch == 0:
            return "Unknown"
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        return "Unknown"


def prettyJson(data: dict = {}):
    res = json.dumps(
        data, sort_keys=True, default=str, indent=4, separators=(",", ": ")
    )
    return res


def pb(boolIn: bool):
    if boolIn:
        return "Yes"
    else:
        return "No"


def numberFormat(value):
    return format(int(value), ",d")


_main_css_hash = None


def main_css_hash():
    return ""
    # TODO
    global _main_css_hash
    if _main_css_hash is None:
        if MAIN_CSS_HASH and MAIN_CSS_HASH != "auto":
            _main_css_hash = MAIN_CSS_HASH
        else:
            src = "assets/main.css"
            _main_css_hash = hashlib.md5(open(src, "rb").read()).hexdigest()
            dst = f"assets/main-{_main_css_hash}.css"

            do_copy = True
            current_mains = glob.glob("assets/main-*.css")
            if current_mains:
                if current_mains[0].endswith(f"main-{_main_css_hash}.css"):
                    do_copy = False
                else:
                    print("Removing: ", current_mains)
                    for m in current_mains:
                        os.remove(m)
            if do_copy:
                shutil.copyfile(src, dst)

    return _main_css_hash


def renderTemplate(filename: str, params: dict = {}, status_code: int = 200) -> tuple[str, int]:
    params.update({"url_prefix": env_var("URL_PREFIX", "http://localhost:5001")})

    pbe = env_var("PHASE_BANNER", "PRIVATE-ALPHA")
    params.update({"phase_banner": pbe})
    params.update(
        {
            "phase_banner_class": (
                "red_phase"
                if any(
                    m in pbe.upper() for m in ["NONPROD", "LOCALHOST", "TEST", "DEV"]
                )
                else ""
            )
        }
    )

    params.update({"domain": env_var("DOMAIN")})

    params.update({"main_css_suffix": ""})  # f"-{main_css_hash()}"})

    templateLoader = jinja2.FileSystemLoader(searchpath="./templates")
    templateEnv = jinja2.Environment(loader=templateLoader)

    templateEnv.globals["prettyJson"] = prettyJson
    templateEnv.globals["colourFromLetter"] = colourFromLetter
    templateEnv.globals["pb"] = pb
    templateEnv.globals["datetimeFromEpoch"] = datetimeFromEpoch
    templateEnv.globals["numberFormat"] = numberFormat

    template = templateEnv.get_template(filename)
    return template.render(params), status_code
