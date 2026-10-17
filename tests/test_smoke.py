"""Tests de fumée AgAtA — lancer avec : pytest -q
Par défaut : SQLite temporaire initialisée avec l'ANCIEN schéma (pour tester la migration Alembic).
Sur PostgreSQL : TEST_DATABASE_URL=postgresql://user@host/base_vide pytest -q
"""
import os
import pathlib
import re
import sqlite3
import sys
import tempfile

_tmp = tempfile.mkdtemp()
_pg = os.getenv("TEST_DATABASE_URL")
os.environ.update({
    "DATABASE_URL": _pg or f"sqlite:///{_tmp}/test.db",
    "DEV_SECRETS_FILE": f"{_tmp}/secrets.json",
    "ENVIRONMENT": "development",
    "REDIS_URL": "",
    "FREE_CREDITS": "3",
    "PLATFORM_OPENAI_KEY": "sk-platform-test-key-123456",
    "MAIL_PROVIDER": "console",
    "REQUIRE_VERIFIED_EMAIL": "1",
    "ADMIN_EMAIL": "",
})
if not _pg:  # ancien schéma (version 3 du fichier d'origine) : la migration 0001 doit l'adapter
    with sqlite3.connect(f"{_tmp}/test.db") as con:
        con.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255) UNIQUE, pw VARCHAR(255), role VARCHAR(10), credits INTEGER);
        CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, kind VARCHAR(10), title VARCHAR(200), body TEXT,
                            status VARCHAR(10), reason VARCHAR(300), votes INTEGER, created TIMESTAMP);
        CREATE TABLE passkeys (id INTEGER PRIMARY KEY, user_id INTEGER, cred_id VARCHAR(512) UNIQUE, pub TEXT, count INTEGER);
        """)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import inspect, select, update  # noqa: E402

import main  # noqa: E402

main.run_migrations()  # alembic upgrade head


@pytest.fixture(autouse=True)
def reset_limits():
    main._hits.clear()
    main.SENT_MAIL.clear()
    yield


def client():
    return TestClient(main.app)


def register(c, email, password="motdepasse-long", verify=False):
    r = c.post("/api/register", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    if verify:
        assert c.post("/api/email/verify", json={"token": last_token("verify")}).status_code == 200
    return c


def last_token(kind):
    """Extrait le jeton du dernier e-mail « envoyé » (mode console)."""
    return re.search(rf"\?{kind}=([\w-]+)", main.SENT_MAIL[-1]["text"]).group(1)


def test_health_and_ready():
    c = client()
    assert c.get("/healthz").json() == {"ok": True}
    assert c.get("/readyz").json()["database"] == "ok"


def test_alembic_schema_at_head():
    insp = inspect(main.engine)
    cols = {c["name"] for c in insp.get_columns("posts")}
    assert "created_at" in cols and "created" not in cols
    assert {"active", "email_verified", "token_version"} <= {c["name"] for c in insp.get_columns("users")}
    assert "email_tokens" in insp.get_table_names()
    with main.engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar() == "0002_email_tokens"
    main.run_migrations()  # idempotent


def test_auth_flow_and_logout_revokes_token():
    c = client()
    assert c.get("/api/me").status_code == 401
    register(c, "test@example.com")
    assert c.post("/api/register", json={"email": "test@example.com", "password": "motdepasse-long"}).status_code == 409
    me = c.get("/api/me").json()
    assert me["email"] == "test@example.com" and me["role"] == "user"
    token = c.cookies.get("agata_session")
    assert c.post("/api/logout").status_code == 200
    c.cookies.set("agata_session", token)  # rejouer le jeton après déconnexion
    assert c.get("/api/me").status_code == 401
    assert c.post("/api/login", json={"email": "test@example.com", "password": "mauvais-mdp-123"}).status_code == 401
    assert c.post("/api/login", json={"email": "TEST@example.com", "password": "motdepasse-long"}).status_code == 200


def test_admin_email_not_granted_by_password_signup(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_EMAIL", "boss@example.com")
    c = register(client(), "boss@example.com")
    assert c.get("/api/me").json()["role"] == "user"


def test_csrf_origin_blocked():
    c = client()
    r = c.post("/api/login", json={"email": "a@b.co", "password": "x" * 12}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_csp_nonce_on_home():
    r = client().get("/")
    nonce = r.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in r.text and "__NONCE__" not in r.text
    assert "onclick=" not in r.text  # aucun gestionnaire inline (CSP stricte)


def test_ssrf_blocked():
    for url in ["https://127.0.0.1", "http://example.com", "https://localhost", "https://10.0.0.1/v1",
                "https://user:pw@example.com", "https://example.com:8443"]:
        with pytest.raises(HTTPException):
            main.safe_custom_url(url)


def test_encryption_roundtrip_and_legacy():
    blob = main.encrypt_secret(1, "openai", {"key": "x"})
    assert main.decrypt_secret(1, "openai", blob) == ({"key": "x"}, False)
    # Format de l'ancienne version (dérivation "user:<id>")
    import base64, json, secrets as s
    n = s.token_bytes(12)
    ct = main.AESGCM(main.user_key(1, legacy=True)).encrypt(n, json.dumps({"key": "y"}).encode(), b"1:openai")
    assert main.decrypt_secret(1, "openai", base64.b64encode(n + ct).decode()) == ({"key": "y"}, True)
    with pytest.raises(HTTPException):
        main.decrypt_secret(2, "openai", blob)  # autre utilisateur : refus


def test_scrub():
    out = main.scrub("Écris à jean@mail.com ou +243 812 345 678, clé sk-abcdefghijklmnopqrstu")
    assert "jean@mail.com" not in out and "812" not in out and "sk-abc" not in out


def test_chat_credits_debit_and_refund(monkeypatch):
    c = register(client(), "chat@example.com")
    r = c.post("/api/chat", json={"prompt": "Salut", "targets": [{"provider": "openai"}]})
    assert r.status_code == 403  # crédits offerts réservés aux e-mails confirmés
    assert c.post("/api/email/verify", json={"token": last_token("verify")}).status_code == 200

    async def ok(provider, key, base, model, prompt, system=None):
        return "bonjour"

    async def ko(*a, **k):
        raise main.ProviderError("openai", "OpenAI a refusé la requête (HTTP 500).")

    monkeypatch.setattr(main, "call_model", ok)
    r = c.post("/api/chat", json={"prompt": "Salut", "targets": [{"provider": "openai"}]})
    assert r.status_code == 200 and r.json()["results"][0]["text"] == "bonjour"
    assert c.get("/api/me").json()["credits"] == 2
    monkeypatch.setattr(main, "call_model", ko)
    r = c.post("/api/chat", json={"prompt": "Salut", "targets": [{"provider": "openai"}]})
    assert r.json()["refunded"] == 1 and c.get("/api/me").json()["credits"] == 2
    r = c.post("/api/chat", json={"prompt": "x", "targets": [{"provider": "mistral"}]})
    assert r.status_code == 400  # aucune clé pour Mistral


def test_chat_stream_refund_on_error(monkeypatch):
    c = register(client(), "stream@example.com", verify=True)

    async def broken(*a, **k):
        raise main.ProviderError("openai", "panne")
        yield  # pragma: no cover

    async def fine(*a, **k):
        for part in ("Bon", "jour"):
            yield part

    monkeypatch.setattr(main, "stream_model", fine)
    body = c.post("/api/chat/stream", json={"prompt": "x", "targets": [{"provider": "openai"}]}).text
    assert '"delta": "Bon"' in body and '"end": true' in body
    assert c.get("/api/me").json()["credits"] == 2
    monkeypatch.setattr(main, "stream_model", broken)
    body = c.post("/api/chat/stream", json={"prompt": "x", "targets": [{"provider": "openai"}]}).text
    assert '"refunded": 1' in body and c.get("/api/me").json()["credits"] == 2


def test_keys_vault():
    c = register(client(), "vault@example.com")
    assert c.post("/api/keys", json={"provider": "openai", "key": "sk-user-key-abcdef"}).status_code == 200
    keys = c.get("/api/keys").json()
    assert keys == [{"provider": "openai", "label": ""}]  # la clé n'est jamais renvoyée
    assert c.post("/api/keys", json={"provider": "custom", "key": "abcdefgh", "base_url": "https://127.0.0.1"}).status_code == 400
    assert c.delete("/api/keys/openai").json() == {"ok": True} and c.get("/api/keys").json() == []


def test_posts_votes_and_moderation(monkeypatch):
    async def approve(title, body):
        return "approve", "ok"
    monkeypatch.setattr(main, "moderate", approve)
    c = register(client(), "poster@example.com")
    assert c.post("/api/posts", json={"kind": "post", "title": "Titre", "body": "Corps"}).status_code == 403
    c.post("/api/email/verify", json={"token": last_token("verify")})
    assert c.post("/api/posts", json={"kind": "prompt", "title": "Mon prompt", "body": "Explique X"}).json()["status"] == "published"
    feed = c.get("/api/posts").json()
    pid = feed["items"][0]["id"]
    assert c.post(f"/api/posts/{pid}/vote").json() == {"votes": 1, "voted": True}
    assert c.post(f"/api/posts/{pid}/vote").json() == {"votes": 0, "voted": False}  # retrait
    assert c.post(f"/api/admin/posts/{pid}/remove").status_code == 403


@pytest.mark.anyio
async def test_moderation_rejects_secrets():
    assert (await main.moderate("titre", "ma clé sk-abcdefghijklmnopqrstuv"))[0] == "reject"


def test_oauth_prehijack_protection(monkeypatch):
    attacker = register(client(), "victim@example.com")
    attacker.post("/api/keys", json={"provider": "openai", "key": "sk-attacker-key-xyz"})

    async def verified(provider, code):
        return "victim@example.com"
    monkeypatch.setattr(main, "fetch_verified_email", verified)
    monkeypatch.setenv("OAUTH_GOOGLE_ID", "id")
    victim = client()
    r = victim.get("/auth/google/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1].split("&")[0]
    r = victim.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert victim.get("/api/me").json()["verified"] is True
    assert attacker.get("/api/me").status_code == 401           # session de l'attaquant révoquée
    assert victim.get("/api/keys").json() == []                  # clé piégée supprimée
    assert client().post("/api/login", json={"email": "victim@example.com", "password": "motdepasse-long"}).status_code == 401
    r = victim.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
    assert "auth_error" in r.headers["location"]                 # state à usage unique


def test_rate_limit():
    for _ in range(3):
        main.rate_limit("unit-test", 3, 60)
    with pytest.raises(HTTPException) as exc:
        main.rate_limit("unit-test", 3, 60)
    assert exc.value.status_code == 429


def test_email_verification_flow():
    c = register(client(), "verif@example.com")
    assert c.get("/api/me").json()["verified"] is False
    mail = main.SENT_MAIL[-1]
    assert mail["to"] == "verif@example.com" and "?verify=" in mail["text"]
    token = last_token("verify")
    assert client().post("/api/email/verify", json={"token": token}).status_code == 401  # session requise
    other = register(client(), "autre@example.com")
    assert other.post("/api/email/verify", json={"token": token}).status_code == 403    # autre compte
    # Le jeton n'a pas été consommé par les tentatives refusées
    assert c.post("/api/email/verify", json={"token": token}).status_code == 200
    assert c.get("/api/me").json()["verified"] is True
    assert c.post("/api/email/verify", json={"token": token}).status_code == 400        # usage unique
    assert c.post("/api/email/verify/send").json()["already"] is True


def test_resend_verification_invalidates_previous_link():
    c = register(client(), "renvoi@example.com")
    first = last_token("verify")
    assert c.post("/api/email/verify/send").status_code == 200
    second = last_token("verify")
    assert first != second
    assert c.post("/api/email/verify", json={"token": first}).status_code == 400
    assert c.post("/api/email/verify", json={"token": second}).status_code == 200


def test_admin_granted_after_verification(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_EMAIL", "chef@example.com")
    c = register(client(), "chef@example.com")
    assert c.get("/api/me").json()["role"] == "user"
    c.post("/api/email/verify", json={"token": last_token("verify")})
    assert c.get("/api/me").json()["role"] == "admin"


def test_forgot_password_no_enumeration():
    register(client(), "oubli@example.com")
    main.SENT_MAIL.clear()
    a = client().post("/api/password/forgot", json={"email": "oubli@example.com"})
    b = client().post("/api/password/forgot", json={"email": "inconnu@example.com"})
    assert a.status_code == b.status_code == 200 and a.json() == b.json()
    assert len(main.SENT_MAIL) == 1 and main.SENT_MAIL[0]["to"] == "oubli@example.com"


def test_password_reset_flow():
    owner = register(client(), "reset@example.com", verify=True)
    client().post("/api/password/forgot", json={"email": "reset@example.com"})
    token = last_token("reset")
    assert client().post("/api/password/reset", json={"token": "x" * 30, "new_password": "nouveau-mdp-123"}).status_code == 400
    c = client()
    assert c.post("/api/password/reset", json={"token": token, "new_password": "nouveau-mdp-123"}).status_code == 200
    assert c.get("/api/me").json()["email"] == "reset@example.com"            # connecté directement
    assert owner.get("/api/me").status_code == 401                             # anciennes sessions fermées
    assert client().post("/api/password/reset", json={"token": token, "new_password": "encore-autre-1"}).status_code == 400
    login = {"email": "reset@example.com"}
    assert client().post("/api/login", json={**login, "password": "motdepasse-long"}).status_code == 401
    assert client().post("/api/login", json={**login, "password": "nouveau-mdp-123"}).status_code == 200


def test_reset_token_expiry():
    register(client(), "expire@example.com")
    client().post("/api/password/forgot", json={"email": "expire@example.com"})
    token = last_token("reset")
    with main.SessionLocal() as db:
        db.execute(update(main.EmailToken).where(main.EmailToken.token_hash == main.hash_token(token))
                   .values(expires_at=main.utcnow() - main.timedelta(minutes=1)))
        db.commit()
    r = client().post("/api/password/reset", json={"token": token, "new_password": "nouveau-mdp-123"})
    assert r.status_code == 400


def test_reset_purges_impostor():
    """Un imposteur crée un compte avec l'adresse de la victime et y dépose sa clé API.
    La victime utilise « mot de passe oublié » : l'imposteur perd tout accès."""
    impostor = register(client(), "cible@example.com")
    impostor.post("/api/keys", json={"provider": "openai", "key": "sk-impostor-key-123"})
    client().post("/api/password/forgot", json={"email": "cible@example.com"})
    victim = client()
    victim.post("/api/password/reset", json={"token": last_token("reset"), "new_password": "victime-mdp-123"})
    assert impostor.get("/api/me").status_code == 401
    assert victim.get("/api/keys").json() == []
    assert victim.get("/api/me").json()["verified"] is True
    with main.SessionLocal() as db:
        assert db.scalar(select(main.User.email_verified).where(main.User.email == "cible@example.com")) is True
