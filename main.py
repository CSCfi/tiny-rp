"""Tiny OpenID Connect Relaying Party Client."""

import os
import sys
import json
import secrets
import logging

from urllib.parse import urlencode
from typing import Tuple

import httpx

from fastapi import FastAPI, Cookie
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware


# distutils.util.strtobool was deprecated in python 3.12 here is the source code for the simple function
# https://github.com/pypa/distutils/blob/94942032878d431cee55adaab12a8bd83549a833/distutils/util.py#L340-L353
def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value {!r}".format(val))


# logging
formatting = "[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(module)s | %(funcName)s: %(message)s"
logging.basicConfig(
    level=logging.DEBUG if bool(strtobool(os.environ.get("DEBUG", "False"))) else logging.INFO, format=formatting
)
LOG = logging.getLogger("tiny-rp")

# configuration
config_file = os.environ.get("CONFIG_FILE", "config.json")
CONFIG = {}
try:
    with open(config_file, "r") as f:
        LOG.info(f"loading configuration file {config_file}")
        CONFIG = json.loads(f.read())
        LOG.info("configuration loaded")
        LOG.debug(CONFIG)
except Exception as e:
    LOG.error(f"failed to load configuration file {config_file}, {e}")
    sys.exit(e)


def get_configs():
    """Request OpenID configuration from OpenID provider."""
    with httpx.Client(verify=False) as client:
        LOG.debug(f"requesting OpenID configuration from {CONFIG['url_oidc']}")
        response = client.get(CONFIG["url_oidc"])
        if response.status_code == 200:
            # store URLs for later use
            LOG.debug("OpenID configuration received")
            data = response.json()
            CONFIG["url_auth"] = data.get("authorization_endpoint", "")
            CONFIG["url_token"] = data.get("token_endpoint", "")
            CONFIG["url_revoke"] = data.get("revocation_endpoint", "")
            CONFIG["url_userinfo"] = data.get("userinfo_endpoint", "")
            LOG.debug(f"new config: {CONFIG}")
        else:
            # we can't proceed without these URLs
            LOG.error(f"failed to request OpenID configuration: {response.status_code}")
            sys.exit(f"failed to retrieve OIDC configuration: {response.status_code}")


get_configs()

# the web app
app = FastAPI()
# add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["cors_domains"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def index_endpoint(id_token: str = Cookie("")):
    """Index can be used as a health check endpoint."""
    LOG.debug("request to index")
    response = """
            <ul>
                <li><a href="/login">login</a></li>
            </ul>
            """
    if id_token:
        response = """
            <ul>
                <li><a href="/token">token</a></li>
                <li><a href="/userinfo">userinfo</a></li>
                <li><a href="/logout">logout</a></li>
            </ul>
            """
    return HTMLResponse(response)


@app.get("/login/")
async def login_endpoint():
    """Redirect the user to sign in at OpenID provider."""
    LOG.debug("request to login")

    # create parameters for authorisation request
    LOG.debug("generating state for authorisation request")
    state = secrets.token_hex()
    LOG.debug(f"state: {state}")
    params = {
        "client_id": CONFIG["client_id"],
        "response_type": "code",
        "state": state,
        "redirect_uri": CONFIG["url_callback"],
        "scope": CONFIG["scope"],
    }
    # optional param for special cases
    if "resource" in CONFIG:
        params["resource"] = CONFIG["resource"]

    # prepare the redirection response
    url = CONFIG["url_auth"] + "?" + urlencode(params)
    LOG.debug(f"authorisation URL: {url}")
    response = RedirectResponse(url)

    # store state cookie for callback verification
    response.set_cookie(
        key="oidc_state", value=state, max_age=300, httponly=True, secure=True, domain=CONFIG.get("cookie_domain", None)
    )

    # redirect user to sign in at OpenID provider
    LOG.debug("redirecting to OpenID provider")
    return response


@app.get("/callback/")
async def callback_endpoint(oidc_state: str = Cookie(""), state: str = "", code: str = ""):
    """Receive the user back from OpenID provider and then retrieves tokens."""
    LOG.debug("request to callback")

    # check that state is set to cookies
    if oidc_state == "":
        LOG.error("'oidc_state' cookie is missing")
        raise HTTPException(401, "uninitialised session")
    LOG.debug(f"cookie: oidc_state={oidc_state}")

    # check that state was received from OpenID provider
    if state == "":
        LOG.error("'state' query param is missing")
        raise HTTPException(400, "missing required query parameter 'state'")
    LOG.debug(f"query param: state={state}")

    # check that authorisation code was received from OpenID provider
    if code == "":
        LOG.error("'code' query param is missing")
        raise HTTPException(400, "missing required query parameter 'code'")
    LOG.debug(f"query param: code={code}")

    # verify that states match
    if not secrets.compare_digest(oidc_state, state):
        LOG.error(f"cookie state and query param state don't match: {oidc_state}!={state}")
        raise HTTPException(403, "state mismatch")
    LOG.debug("cookie state and query param state matched")

    # get tokens using the code received after authentication
    LOG.debug("get tokens")
    id_token, access_token = await request_tokens(code)
    LOG.debug(f"id_token={id_token}, access_token={access_token}")

    if CONFIG["url_redirect"] == "":
        # display tokens
        LOG.debug("redirect address is not set, display tokens in JSON")
        return {"id_token": id_token, "access_token": access_token}
    else:
        # save tokens to cookies and redirect
        LOG.debug(f"save tokens to cookies and redirect user to {CONFIG['url_redirect']}")

        # prepare the redirection response
        response = RedirectResponse(CONFIG["url_redirect"])

        # store tokens to cookies
        response.set_cookie(
            key="id_token",
            value=id_token,
            max_age=3600,
            httponly=True,
            secure=True,
            domain=CONFIG.get("cookie_domain", None),
        )
        response.set_cookie(
            key="access_token",
            value=access_token,
            max_age=3600,
            httponly=True,
            secure=True,
            domain=CONFIG.get("cookie_domain", None),
        )
        response.set_cookie(
            key="logged_in",
            value="True",
            max_age=3600,
            httponly=False,
            secure=True,
            domain=CONFIG.get("cookie_domain", None),
        )

        # redirect user
        LOG.debug(f"redirecting to {CONFIG['url_redirect']}")
        return response


@app.get("/logout")
async def logout_endpoint(id_token: str = Cookie(""), access_token: str = Cookie("")):
    LOG.debug("request to logout")

    # revoke tokens at issuer
    await revoke_token(id_token)
    await revoke_token(access_token)

    # prepare the redirection response
    response = RedirectResponse(CONFIG["url_redirect"])

    # overwrite cookies with instantly expiring ones
    response.set_cookie(
        key="id_token", value="", max_age=0, httponly=True, secure=True, domain=CONFIG.get("cookie_domain", None)
    )
    response.set_cookie(
        key="access_token", value="", max_age=0, httponly=True, secure=True, domain=CONFIG.get("cookie_domain", None)
    )
    response.set_cookie(
        key="logged_in", value="", max_age=0, httponly=False, secure=True, domain=CONFIG.get("cookie_domain", None)
    )

    # redirect user
    LOG.debug(f"redirecting to {CONFIG['url_redirect']}")
    return response


async def request_tokens(code: str) -> Tuple[str, str]:
    """Request tokens from OpenID provider."""
    LOG.debug(f"set up token request using code: {code}")

    # set up basic auth and payload
    auth = httpx.BasicAuth(username=CONFIG["client_id"], password=CONFIG["client_secret"])
    LOG.debug("basic auth is set")
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": CONFIG["url_callback"]}
    LOG.debug(f"post payload: {data}")

    async with httpx.AsyncClient(auth=auth, verify=False) as client:
        # request tokens
        LOG.debug("requesting tokens")
        response = await client.post(CONFIG["url_token"], data=data)
        if response.status_code == 200:
            # return token strings
            LOG.debug("received tokens")
            r = response.json()
            return r["id_token"], r["access_token"]
        else:
            # if something went wrong on the provider side, we need to abort
            LOG.error(f"didn't receive tokens from OpenID provider: {response.status_code}")
            raise HTTPException(500, f"failed to retrieve tokens from provider: {response.status_code}")


async def revoke_token(token: str) -> None:
    """Request token revocation at AAI."""
    LOG.debug("revoking token")

    auth = httpx.BasicAuth(username=CONFIG["client_id"], password=CONFIG["client_secret"])
    params = {"token": token}

    async with httpx.AsyncClient(auth=auth, verify=False) as client:
        # send request to AAI
        response = await client.get(CONFIG["url_revoke"] + "?" + urlencode(params))
        if response.status_code == 200:
            LOG.debug("tokens revoked successfully")
        else:
            LOG.error(f"failed to revoke tokens {response.status_code}, remove cookies in any case and redirect")


@app.get("/token")
async def token_endpoint(id_token: str = Cookie(""), access_token: str = Cookie("")):
    LOG.debug("display token from cookies in JSON response")

    response = {
        "id_token": id_token,
        "access_token": access_token,
    }

    return JSONResponse(response)


@app.get("/userinfo")
async def userinfo_endpoint(access_token: str = Cookie("")):
    LOG.debug("fetch userinfo from AAI")

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        # request tokens
        LOG.debug("requesting userinfo")
        response = await client.post(CONFIG["url_userinfo"])
        if response.status_code == 200:
            # return userinfo content
            LOG.debug("received userinfo")
            r = response.json()
            return r
        else:
            # if something went wrong on the provider side, we need to abort
            LOG.error(f"didn't receive userinfo from OpenID provider: {response.status_code}")
            raise HTTPException(500, f"failed to retrieve userinfo from provider: {response.status_code}")
