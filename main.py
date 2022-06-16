"""Tiny OpenID Connect Relaying Party Client."""

import os
import sys
import json
import secrets
import logging
from tokenize import String

from urllib.parse import urlencode
from distutils.util import strtobool
from typing import Tuple

import httpx

import aiohttp
from typing import Optional

from fastapi import FastAPI, Cookie
from fastapi.exceptions import HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from authlib.jose import jwt
from authlib.jose import JWTClaims

import base64
import ujson
from typing import Dict, List, Tuple
# the web app
app = FastAPI()

# logging
formatting = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(module)s | %(funcName)s: %(message)s'
logging.basicConfig(level=logging.DEBUG if bool(strtobool(os.environ.get('DEBUG', 'False'))) else logging.INFO, format=formatting)
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


@app.on_event("startup")
async def startup_event():
    """Request OpenID configuration from OpenID provider."""
    # add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CONFIG["cors_domains"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # get missing OIDC configurations
    async with httpx.AsyncClient(verify=False) as client:
        # request OpenID provider endpoints from their configuration
        LOG.debug(f"requesting OpenID configuration from {CONFIG['url_oidc']}")
        response = await client.get(CONFIG["url_oidc"])
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


@app.get("/")
async def index_endpoint():
    """Index can be used as a health check endpoint."""
    LOG.debug("request to index")
    return PlainTextResponse("tiny-rp")


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
        "scope": CONFIG["scope"]
    }

    # prepare the redirection response
    url = CONFIG["url_auth"] + "?" + urlencode(params)
    LOG.debug(f"authorisation URL: {url}")
    response = RedirectResponse(url)

    # store state cookie for callback verification
    response.set_cookie(key="oidc_state",
                        value=state,
                        max_age=300,
                        httponly=True,
                        secure=True,
                        domain=CONFIG.get("cookie_domain", None))

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
        response.set_cookie(key="id_token",
                            value=id_token,
                            max_age=3600,
                            httponly=True,
                            secure=True,
                            domain=CONFIG.get("cookie_domain", None))
        response.set_cookie(key="access_token",
                            value=access_token,
                            max_age=3600,
                            httponly=True,
                            secure=True,
                            domain=CONFIG.get("cookie_domain", None))
        response.set_cookie(key="logged_in",
                            value="True",
                            max_age=3600,
                            httponly=False,
                            secure=True,
                            domain=CONFIG.get("cookie_domain", None))

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
    response.set_cookie(key="id_token",
                        value="",
                        max_age=0,
                        httponly=True,
                        secure=True,
                        domain=CONFIG.get("cookie_domain", None))
    response.set_cookie(key="access_token",
                        value="",
                        max_age=0,
                        httponly=True,
                        secure=True,
                        domain=CONFIG.get("cookie_domain", None))
    response.set_cookie(key="logged_in",
                        value="",
                        max_age=0,
                        httponly=False,
                        secure=True,
                        domain=CONFIG.get("cookie_domain", None))

    # redirect user
    LOG.debug(f"redirecting to {CONFIG['url_redirect']}")
    return response


async def request_tokens(code: str) -> Tuple[str, str]:
    """Request tokens from OpenID provider."""
    LOG.debug(f"set up token request using code: {code}")

    # set up basic auth and payload
    auth = httpx.BasicAuth(username=CONFIG["client_id"], password=CONFIG["client_secret"])
    LOG.debug("basic auth is set")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CONFIG["url_callback"]
    }
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
async def token_endpoint(access_token: str = Cookie("")):
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
            r["Dataset access"] = []
            passportList = []
            for passportVisas in r["ga4gh_passport_v1"]:
                decoded = await decode_passport(passportVisas)
               
                if decoded != "":
                    r["Dataset access"].append(decoded)
                
                if decoded == "AcceptedTermsAndPoliciesTrue":
                    passportList.append(decoded)
                if decoded == "ResearcherStatusTrue":
                    passportList.append(decoded)
            if await get_ga4gh_bona_fide(passportList):
                r["Bona fide status"] = "Verified"
            else:
                r["Bona fide status"] = "Unverified"  
            r.pop("given_name", None)
            r.pop("family_name", None)
            r.pop("ga4gh_passport_v1", None)
            r["email"] = r["email"], r["email_verified"]
            r.pop("email_verified", None)

            return r
        else:
            # if something went wrong on the provider side, we need to abort
            LOG.error(f"didn't receive userinfo from OpenID provider: {response.status_code}")
            raise HTTPException(500, f"failed to retrieve userinfo from provider: {response.status_code}")


async def decode_passport(encoded_passport: str) -> List[Dict]:
    """Return decoded header and payload from encoded passport JWT.
    Public-key-less decoding inspired by the PyJWT library https://github.com/jpadilla/pyjwt
    This function is originally from https://github.com/CSCfi/beacon-python with some changes made to suit the needs of this project.
    """
    LOG.debug("Decoding GA4GH passport.")

    # Convert the token string into bytes for processing, and split it into segments
    decoded_passport = encoded_passport.encode("utf-8")  # `header.payload.signature`
    data, _ = decoded_passport.rsplit(b".", 1)  # data contains header and payload segments, the ignored segment is the signature segment
    segments = data.split(b".", 1)  # [header, payload]

    # Intermediary container
    verified_segments = []
    # Handle different implementations of public exponent
    # 65537 is recommended, but some use 65536 instead
    # pad the missing bytes, if needed
    for segment in segments:
        rem = len(segment) % 4
        if rem > 0:
            segment += b"=" * (4 - rem)
        verified_segments.append(segment)

    # Decode the verified token segments
    decoded_segments = [base64.urlsafe_b64decode(seg) for seg in verified_segments]

    # Convert the decoded segment bytes into dicts for easy access
    decoded_data = [ujson.loads(seg.decode("utf-8")) for seg in decoded_segments]
    if decoded_data[1]["ga4gh_visa_v1"]["type"] == "ControlledAccessGrants":
        return decoded_data[1]["ga4gh_visa_v1"]["value"]
    elif decoded_data[1]["ga4gh_visa_v1"]["type"]  == "AcceptedTermsAndPolicies":
        return "AcceptedTermsAndPoliciesTrue"
    elif decoded_data[1]["ga4gh_visa_v1"]["type"]  == "ResearcherStatusTrue":
        return "ResearcherStatusTrue"
    else:
        return ""    
        

async def get_ga4gh_bona_fide(passports: List) -> bool:
    """Retrieve Bona Fide status from GA4GH JWT claim.
    This function is originally from https://github.com/CSCfi/beacon-python"""
    LOG.info("Parsing GA4GH bona fide claims.")

    # User must have agreed to terms, and been recognized by a peer to be granted Bona Fide status
    terms = False
    status = False

    for passport in passports:
        # Check for the `type` of visa to determine if to look for `terms` or `status`
        #
        # CHECK FOR TERMS
        passport_type = passport[2].get("ga4gh_visa_v1", {}).get("type")
        passport_value = passport[2].get("ga4gh_visa_v1", {}).get("value")
        if passport_type in "AcceptedTermsAndPolicies" and passport_value == "https://doi.org/10.1038/s41431-018-0219-y":
            # This passport has the correct type and value, next step is to validate it
            #
            # Decode passport and validate its contents
            # If the validation passes, terms will be set to True
            # If the validation fails, an exception will be raised
            # (and ignored since it's not fatal), and terms will remain False
            await validate_passport(passport)
            # The token is validated, therefore the terms are accepted
            terms = True
        #
        # CHECK FOR STATUS
        if passport_value == "https://doi.org/10.1038/s41431-018-0219-y" and passport_type == "ResearcherStatus":
            # Check if the visa contains a bona fide value
            # This passport has the correct type and value, next step is to validate it
            #
            # Decode passport and validate its contents
            # If the validation passes, status will be set to True
            # If the validation fails, an exception will be raised
            # (and ignored since it's not fatal), and status will remain False
            await validate_passport(passport)
            # The token is validated, therefore the status is accepted
            status = True

        # User has agreed to terms and has been recognized by a peer, return True for Bona Fide status
    return terms and status

async def validate_passport(passport: Dict) -> JWTClaims:
    """Decode a passport and validate its contents.
    This function is originally from https://github.com/CSCfi/beacon-python"""
    LOG.debug("Validating passport.")

    # Passports from `get_ga4gh_controlled()` will be of form
    # passport[0] -> encoded passport (JWT)
    # passport[1] -> unverified decoded header (contains `jku`)
    # Passports from `get_bona_fide_status()` will be of form
    # passport[0] -> encoded passport (JWT)
    # passport[1] -> unverified decoded header (contains `jku`)
    # passport[2] -> unverified decoded payload

    # JWT decoding and validation settings
    # The `aud` claim will be ignored, because Beacon has no prior knowledge
    # as to where the token has originated from, and is therefore unable to
    # verify the intended audience. Other claims will be validated as per usual.
    claims_options = {"aud": {"essential": False}}

    # Attempt to decode the token and validate its contents
    # None of the exceptions are fatal, and will not raise an exception
    # Because even if the validation of one passport fails, the query
    # Should still continue in case other passports are valid
    try:
        # Get JWK for this passport from a third party provider
        # The JWK will be requested from a URL that is given in the `jku` claim in the header
        passport_key = await get_jwk(passport[1].get("jku"))
        # Decode the JWT using public key
        decoded_passport = jwt.decode(passport[0], passport_key, claims_options=claims_options)
        # Validate the JWT signature
        decoded_passport.validate()
        # Return decoded and validated payload contents
        return decoded_passport
    except Exception as e:
        LOG.error(f"Something went wrong when processing JWT tokens: {e}")

async def get_jwk(url: str) -> Optional[Dict]:
    """Get JWK set keys to validate JWT.
    This function is originally from https://github.com/CSCfi/beacon-python"""
    LOG.debug("Retrieving JWK.")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as r:
                # This can be a single key or a list of JWK
                return await r.json()
    except Exception:
        # This is not a fatal error, it just means that we are unable to validate the permissions,
        # but the process should continue even if the validation of one token fails
        LOG.error(f"Could not retrieve JWK from {url}")
        return None