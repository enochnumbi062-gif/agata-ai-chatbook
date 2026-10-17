# AgAtA-AI-CHATBOOK

Console unique pour interroger, comparer (en streaming) et modérer plusieurs IA (OpenAI, Anthropic, Gemini, Mistral, API compatible), avec un coffre de clés chiffré (AES-256-GCM), une communauté modérée par IA, des passkeys, la connexion Google/GitHub, la vérification d'e-mail et la réinitialisation du mot de passe.

## Structure du dépôt

```
main.py                         Application complète (API FastAPI + interface)
alembic.ini                     Configuration Alembic
migrations/env.py               Environnement Alembic (réutilise les modèles de main.py)
migrations/script.py.mako       Modèle des nouvelles révisions
migrations/versions/0001_baseline.py      Schéma de base (compatible avec les anciennes bases)
migrations/versions/0002_email_tokens.py  Jetons de vérification / réinitialisation
tests/test_smoke.py             23 tests (SQLite et PostgreSQL)
requirements.txt                Dépendances (versions testées)
render.yaml                     Blueprint Render (web + Redis)
.github/workflows/ci-cd.yml     CI : lint, sécurité, migrations, tests, déploiement
.env.example                    Variables d'environnement documentées
.gitignore
```

## Lancer en local

```bash
python -m venv .venv && source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # facultatif
alembic upgrade head                                     # crée / met à jour la base
uvicorn main:app --reload                                # http://localhost:8000
```

En local, `MAIL_PROVIDER=console` affiche les e-mails (avec leurs liens) dans le terminal.

Tests : `pip install pytest anyio && pytest -q -p anyio`

## Déployer sur Render

1. **Pousser sur GitHub**
   ```bash
   git init && git add . && git commit -m "AgAtA v3"
   git branch -M main
   git remote add origin https://github.com/<vous>/agata-ai-chatbook.git
   git push -u origin main
   ```
2. **Base Supabase** : bouton *Connect* → **Session pooler** (hôte `aws-…pooler.supabase.com`, port 5432, utilisateur `postgres.<ref-projet>`). N'utilisez pas la connexion directe `db.<ref>.supabase.co` (IPv6 uniquement, alors que Render est en IPv4), ni le port 6543. Si le mot de passe contient `@ : / # ? %`, encodez-le (ex. `@` → `%40`).
3. **Fournisseur d'e-mails** (obligatoire pour la vérification et le mot de passe oublié). L'offre gratuite de Render **bloque le SMTP** (ports 25, 465, 587), il faut donc une API HTTPS :
   - **Brevo** (300 e-mails/jour gratuits) : créez une clé API, validez votre adresse d'expéditeur (*Senders*), puis `MAIL_PROVIDER=brevo`, `BREVO_API_KEY=…`, `MAIL_FROM=AgAtA <adresse@validée>`.
   - **Resend** : nécessite un nom de domaine vérifié pour écrire à n'importe qui. Réglez `MAIL_PROVIDER=resend`, `RESEND_API_KEY=re_…`, `MAIL_FROM=AgAtA <noreply@votredomaine.com>`.
   - Un domaine à vous (SPF/DKIM configurés) évite que les e-mails arrivent en spam.
4. **Render** : *New → Blueprint*, choisissez le dépôt. Render lit `render.yaml` et crée le service web et Redis. Renseignez les variables marquées `sync: false` : `DATABASE_URL`, `ADMIN_EMAIL`, `MAIL_FROM`, `BREVO_API_KEY` (ou `RESEND_API_KEY`), `PLATFORM_GEMINI_KEY`, et les identifiants OAuth si besoin.
5. **Démarrage** : la commande `alembic upgrade head && uvicorn …` applique les migrations à chaque déploiement. Une ancienne base est mise à niveau sans perte de données.
6. **OAuth (facultatif)** : URL de rappel à déclarer :
   - GitHub : `https://<votre-app>.onrender.com/auth/github/callback`
   - Google : `https://<votre-app>.onrender.com/auth/google/callback`
7. **Admin** : inscrivez-vous avec l'adresse `ADMIN_EMAIL` puis cliquez sur le lien de confirmation (ou connectez-vous avec Google/GitHub). Le rôle admin est attribué à ce moment-là. Vous pouvez aussi lancer `python main.py promote vous@exemple.com` depuis votre machine avec `DATABASE_URL` pointant sur Supabase.
8. **Déploiement automatique** : `render.yaml` contient `autoDeployTrigger: checksPass`. Chaque `git push` sur `main` lance les tests GitHub Actions, et Render ne déploie que s'ils réussissent. N'ajoutez pas le secret `RENDER_DEPLOY_HOOK` : il provoquerait un second déploiement.

⚠️ Ne régénérez jamais `ENCRYPTION_MASTER_KEY` : les clés API déjà enregistrées deviendraient illisibles.

## Faire évoluer le schéma (Alembic)

Le schéma n'est plus créé par l'application. Chaque changement passe par une révision :

```bash
# 1. Modifier les modèles dans main.py (ex. ajouter une colonne)
# 2. Générer la révision
alembic revision --autogenerate -m "ajout colonne avatar"
# 3. Relire le fichier créé dans migrations/versions/, puis appliquer
alembic upgrade head
# 4. Vérifier qu'il ne manque rien (exécuté aussi par la CI)
alembic check
```

Commandes utiles : `alembic current`, `alembic history`, `alembic downgrade -1`.

## Vérification d'e-mail et mot de passe oublié

| Étape | Fonctionnement |
|---|---|
| Inscription | Un lien `/?verify=…` est envoyé (valable 24 h, à usage unique, seule son empreinte SHA-256 est stockée). |
| Confirmation | Le lien doit être ouvert **connecté au même compte** : un imposteur qui aurait créé un compte avec votre adresse ne peut pas le faire valider par vous. |
| Sans confirmation | Connexion et clés personnelles possibles. Publier et utiliser les crédits offerts nécessitent une adresse confirmée (`REQUIRE_VERIFIED_EMAIL=1`). |
| Mot de passe oublié | Réponse identique que le compte existe ou non. Lien `/?reset=…` valable 60 min, à usage unique. |
| Réinitialisation | Nouveau mot de passe, toutes les sessions sont fermées, et l'adresse est confirmée. Si le compte n'était pas confirmé, ses passkeys et clés API sont supprimées (protection contre le pré-détournement de compte). |
