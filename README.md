# Tiny RP
Tiny RP is a small OpenID Connect Relying Party client that authenticates the user at the configured OpenID provider and saves the user's `id_token` and `access_token` to cookies.

## Installation
- Developed with `python 3.8.5`
```
pip install --upgrade pip
pip install -r requirements.txt
```
Dependencies are listed in `requirements.dev.txt`, while versions are set for production in `requirements.txt`.

## Configuration
Configuration variables are set in [config.json](config.json), which resides at the root of the directory.
```
{
    "client_id": "",
    "client_secret": "",
    "url_oidc": "https://openid-provider.org/oidc/.well-known/openid-configuration",
    "url_callback": "http://localhost:8080/callback",
    "url_redirect": "http://localhost:8080/frontend",
    "scope": "openid",
    "cookie_domain": ""
}
```
The app contacts `url_oidc` on startup and retrieves the `authorization_endpoint`, `token_endpoint` and `revocation_endpoint` values, which are used at `/login`, `/callback` and `/logout` respectively.


### Environment Variables
- `CONFIG_FILE=config.json` change location of configuration file
- `DEBUG=True` enable debug logging
- `APP_HOST=localhost` app hostname that can be passed to container
- `APP_PORT=8080` app port that can be passed to container

## Run
### For Development
```
uvicorn main:app --reload
```
### For Deployment
Build image
```
docker build -t cscfi/tiny-rp .
```
Run container
```
docker run -p 8080:8080 cscfi/tiny-rp
```

## Usage
- Navigate to http://localhost:8080/login
- `id_token` and `access_token` are saved to cookies at http://localhost:8080/callback after authentication at OpenID provider
- If a redirect address is configured `url_redirect` (e.g. a UI) the user is redirected there along with the cookies. If left empty, the tokens are instead displayed in JSON.
