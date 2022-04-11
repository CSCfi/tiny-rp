import pytest

from asynctest.mock import patch
from httpx import AsyncClient

from main import app, login_endpoint

MOCK_CONFIG = {
    "client_id": "public",
    "client_secret": "secret",
    "url_oidc": "https://openid-provider.org/oidc/.well-known/openid-configuration",
    "url_auth": "https://openid-provider.org/oidc/authorize",
    "url_token": "https://openid-provider.org/oidc/token",
    "url_callback": "http://localhost:8080/callback",
    "url_redirect": "",
    "scope": "openid",
    "cookie_domain": ""
}


@pytest.mark.asyncio
async def test_index():
    async with AsyncClient(app=app, base_url="http://localhost:8080") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    assert response.text == "tiny-rp"


@pytest.mark.asyncio
@patch("main.CONFIG", return_value=MOCK_CONFIG)
async def test_login_endpoint(m):
    async with AsyncClient(app=app, base_url="http://localhost:8080") as ac:
        response = await ac.get("/login", allow_redirects=False)
        assert response.status_code == 307


@pytest.mark.asyncio
@patch("main.CONFIG", return_value=MOCK_CONFIG)
async def test_callback_endpoint(m):
    async with AsyncClient(app=app, base_url="http://localhost:8080") as ac:
        response = await ac.get("/callback", allow_redirects=False)
        assert response.status_code == 307
