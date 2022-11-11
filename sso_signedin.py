from flask import (
    request,
    session,
    redirect,
)
from functools import wraps
from sso_utils import random_string


def get_csrf_session(override_endpoint: str = None):
    csrf_value = random_string()

    d = {}
    if "csrf_values" in session:
        d = session["csrf_values"]

    d.update({override_endpoint if override_endpoint else request.endpoint: csrf_value})
    session["csrf_values"] = d

    return csrf_value


def CheckCSRFSession(f):
    @wraps(f)
    def wrap(*args, **kwds):
        valid = True

        if "csrf_values" in session and type(session["csrf_values"]) == dict:
            ep = request.endpoint
            if request.method == "POST" and ep in session["csrf_values"]:
                valid = False
                try:
                    from_request = request.form["csrf_form"].strip()
                    session_value = session["csrf_values"][ep]
                    if session_value == from_request:
                        valid = True
                    session["csrf_values"].pop(ep)
                except Exception as e:
                    print("check_csrf_session:e:", e)

        if valid:
            return f(*args, **kwds)
        else:
            return "Forbidden", 403

    return wrap


def UserAlreadySignedIn(f):
    @wraps(f)
    def wrap(*args, **kwds):
        if "signed_in" in session and session["signed_in"]:
            return redirect("/dashboard")
        return f(*args, **kwds)

    return wrap


def UserShouldBeSignedIn(f):
    @wraps(f)
    def wrap(*args, **kwds):
        if "signed_in" in session and session["signed_in"]:
            return f(*args, **kwds)
        session.clear()
        return redirect("/sign-in")

    return wrap
