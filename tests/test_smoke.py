import sys, pathlib, pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fastapi import HTTPException
from fastapi.testclient import TestClient
import main

c = TestClient(main.app)

def test_health():
    assert c.get("/healthz").json() == {"ok": True}

def test_auth_flow():
    assert c.get("/api/me").status_code == 401
    cred = {"email": "test@example.com", "password": "motdepasse-long"}
    assert c.post("/api/register", json=cred).status_code in (200, 409)
    assert c.post("/api/login", json=cred).status_code == 200
    assert c.get("/api/me").json()["email"] == "test@example.com"

def test_ssrf_blocked():
    with pytest.raises(HTTPException):
        main.safe_url("https://127.0.0.1")

def test_encryption_roundtrip():
    assert main.dec(1, "openai", main.enc(1, "openai", {"key": "x"})) == {"key": "x"}
