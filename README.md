# Tiny RP
Tiny RP is a small OpenID Connect Relying Party client that authenticates the user at the configured OpenID provider and saves the user's `id_token` and `access_token` to cookies.

## Installation
- Developed with `python 3.12`
```
pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration
Configuration variables are set as environment variables in a `.env` file. You can start from `.env.example`.
The app contacts `url_oidc` on startup and retrieves the `authorization_endpoint`, `token_endpoint`, `revocation_endpoint` and `userinfo_endpoint` values, which are used at `/login`, `/callback`, `/logout` and `/userinfo` respectively.

### Environment Variables for the container
- `APP_HOST=localhost` app hostname that can be passed to container
- `APP_PORT=8080` app port that can be passed to container

## Run
### For Development
```
cp .env.example .env # <- make changes

uvicorn main:app --reload --env-file .env
```
### For Deployment
The docker image copies `config.json` from the current directory, so either edit the values before building the image, or mount a file with correct values into the container.

Build image
```
docker build -t cscfi/tiny-rp .
```
Run container
```
cp .env.example .env # <- make changes

docker run -p 8080:8080 --env-file .env cscfi/tiny-rp
```

## Usage
- Navigate to http://localhost:8080/login
- `id_token` and `access_token` are saved to cookies at http://localhost:8080/callback after authentication at OpenID provider
- If a redirect address is configured `url_redirect` (e.g. a UI) the user is redirected there along with the cookies. If left empty, the tokens are instead displayed in JSON.
