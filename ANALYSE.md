# Analyse du système AgAtA-AI-CHATBOOK

Fichier analysé : `agata-ai-chatbook.txt` (2 637 lignes). Les numéros de ligne renvoient à ce fichier.

## 1. Constat général

Le fichier n'est pas un script unique. Il contient :

| Lignes | Contenu | État |
|---|---|---|
| 1–4 | Texte « Améliore moi ce système » entre `"""` | À retirer |
| 5–948 | **Version A** de `main.py` (la plus robuste côté serveur, avec streaming) | Base retenue pour le serveur |
| 949–952 | Ligne commençant par `.AgAtA-AI-CHATBOOK — …` hors chaîne | **Erreur de syntaxe Python** : le fichier ne peut pas s'exécuter |
| 953–1818 | **Version B** : quasi-copie de A, sans streaming (comparaison non streamée) | Redondante |
| 1819–2498 | **Version C** : version compacte avec l'interface futuriste (Three.js, radar 2030, HUD) | Base retenue pour l'interface |
| 2499–2637 | `render.yaml`, `test.smoke.py`, `ci-cd.yml`, `.env.example`, `.gitigore` | À corriger |

Coller les trois versions dans un même `main.py` le casse : la ligne 949 bloque l'exécution, et même sans elle chaque version redéfinirait `app`, les modèles SQLAlchemy (erreur « Table 'users' is already defined ») et les routes.

La nouvelle version fusionne le meilleur de chacune : le serveur de A, l'interface de C, plus toutes les corrections listées ci-dessous.

## 2. Failles de sécurité

| # | Où (lignes) | Problème | Gravité | Correction appliquée |
|---|---|---|---|---|
| S1 | A 52–56, C 1836–1837 | Si `JWT_SECRET_KEY` / `ENCRYPTION_MASTER_KEY` manquent, un secret aléatoire est généré **à chaque démarrage** : sessions invalidées et **toutes les clés du coffre deviennent illisibles** après redémarrage (C le fait même en production). | 🔴 Critique | Production : arrêt si secret absent. Développement : secret persistant dans `.agata_dev_secrets.json` (ignoré par git). |
| S2 | A 511–515, C 2042–2046 | `ADMIN_EMAIL` donne le rôle admin **à l'inscription par mot de passe sans vérification d'email** : n'importe qui peut s'inscrire avec l'email de l'admin avant lui. C est pire : sans `ADMIN_EMAIL`, **le premier inscrit devient admin**. | 🔴 Critique | Admin attribué uniquement via Google/GitHub (email vérifié) ou via la commande `python main.py promote email`. |
| S3 | A 761–770, C 2259–2265 | **Pré-détournement de compte** : un attaquant crée un compte avec l'email d'une victime ; quand la victime se connecte avec Google, elle arrive dans le même compte, mais l'attaquant garde son mot de passe et ses passkeys. Il peut aussi y laisser **sa propre clé API**, et les prompts de la victime passent alors par le compte de l'attaquant. | 🔴 Critique | Colonne `email_verified`. Lors de la 1re connexion OAuth sur un compte non vérifié : mot de passe invalidé, sessions révoquées, passkeys et clés supprimées. |
| S4 | C 1930–1931 | `ip()` fait confiance à `X-Forwarded-For` : tout le monde peut **contourner la limitation de débit** en changeant cet en-tête. | 🟠 Élevée | `TRUST_PROXY_HOPS` : on lit seulement l'entrée ajoutée par le proxy de confiance (Render = 1). |
| S5 | A 168–192 | Limiteur Redis : `EXPIRE` est relancé à chaque requête, la fenêtre glisse sans fin. Un client régulier peut rester bloqué indéfiniment. C (1917–1928) : si `EXPIRE` échoue après `INCR`, la clé n'expire jamais. | 🟠 Élevée | Fenêtre fixe par compartiment de temps (`clé:numéro_de_fenêtre`). L'expiration n'est jamais prolongée. |
| S6 | A 787–798, C 2270–2278 | Le défi WebAuthn (cookie `wa`) est **réutilisable** pendant 5 minutes, donc rejouable. | 🟠 Élevée | Nonce à usage unique (Redis `SET NX` ou mémoire). |
| S7 | A 805–807, 824–826 | `UserVerification.REQUIRED` est demandé au navigateur mais **jamais vérifié côté serveur** (`require_user_verification` absent). | 🟠 Élevée | `require_user_verification=True` à l'enregistrement et à la connexion. |
| S8 | A 538–543, C 2059–2062 | La déconnexion supprime le cookie, mais le **JWT reste valable 12 h** s'il a été volé. | 🟡 Moyenne | Révocation par `jti` à la déconnexion, `token_version` pour « déconnecter tous les appareils » et au changement de mot de passe. |
| S9 | A 480–497, C 2021–2026 | La CSP autorise `'unsafe-inline'` pour les scripts, ce qui annule sa protection contre le XSS. Three.js est chargé depuis un CDN sans contrôle d'intégrité (SRI). | 🟡 Moyenne | CSP avec **nonce** par requête, suppression de tous les `onclick=` (délégation d'événements), SRI `sha512` sur Three.js r128. |
| S10 | A/C | Pas de contrôle d'origine : la seule protection CSRF est `SameSite=Strict`. | 🟡 Moyenne | Middleware : `Origin` / `Sec-Fetch-Site` vérifiés sur toutes les requêtes qui modifient des données. |
| S11 | C 1940–1946 | `safe_url` accepte les ports non standard, les identifiants dans l'URL et les noms `.internal`. | 🟡 Moyenne | Port 443 seul, pas d'identifiants, pas de paramètres, liste noire d'hôtes, revérification DNS à chaque appel. |
| S12 | C 1901–1902 | `check_pw` plante (erreur 500) si le hash stocké est malformé, et le temps de réponse révèle si un email existe. | 🟢 Faible | `password_verify` robuste et hash factice calculé une seule fois pour un temps de réponse constant. |
| S13 | A 527–533 | Hash factice recalculé à chaque connexion (scrypt ×2 = CPU gaspillé, petit risque de DoS). | 🟢 Faible | `DUMMY_HASH` calculé une fois au démarrage. |
| S14 | A 371–394 | Le prompt de modération peut être cassé par un `</contenu_non_fiable>` glissé dans le texte. | 🟢 Faible | Les balises sont retirées avant l'envoi. |
| S15 | A 528 | Limite de connexion seulement par IP (du credential stuffing distribué reste possible). | 🟢 Faible | Limite supplémentaire par email haché. |

Limite connue, documentée : la protection SSRF vérifie le DNS puis httpx résout à nouveau le nom (fenêtre de *DNS rebinding*). Pour un blocage total, il faut un proxy de sortie ou épingler l'IP.

## 3. Bugs fonctionnels

| # | Où | Bug | Correction |
|---|---|---|---|
| B1 | A 624–656, C 2192–2224 | **Streaming** : les crédits sont débités mais **jamais remboursés** en cas d'échec (seul `/api/chat` de A rembourse). | Remboursement en fin de flux, dans une session de base dédiée (la session de la requête est déjà fermée à ce moment). |
| B2 | C 2112–2113, 2201–2202 | Débit **non atomique** (`if u.credits < cost: u.credits -= cost`) : deux requêtes simultanées dépensent les mêmes crédits. | `UPDATE … WHERE credits >= cost` (repris de A). |
| B3 | A 679–693, C 2144–2150 | `post.votes += 1` : lecture puis écriture, des votes concurrents se perdent. | `UPDATE posts SET votes = votes + 1`, vote annulable au second clic. |
| B4 | A 316, B 1270 | OpenAI : `max_tokens` est refusé par les modèles récents (o-series, GPT-5…). | `max_completion_tokens` pour OpenAI, `max_tokens` pour Mistral et custom. |
| B5 | C 2176 `timeout=None` | Le streaming peut **bloquer indéfiniment** une connexion. | Timeouts explicites (lecture 120 s). |
| B6 | C 2241–2250 | OAuth : `os.environ[...]` lève `KeyError`, ce qui donne une erreur 500 si la variable est absente. `t.json()` plante si la réponse n'est pas du JSON. Pas de gestion de `?error=access_denied` (l'utilisateur qui annule reçoit une 422). | Lecture via `getenv`, erreurs interceptées, redirection vers `/?auth_error=…` avec message lisible. `state` à usage unique. |
| B7 | C 2259–2263 | Création de compte OAuth sans gestion de course : deux connexions simultanées donnent une erreur 500. | `IntegrityError` interceptée, compte relu. |
| B8 | A 576–583 | `safe_custom_url` (résolution DNS **bloquante**) et la base SQL synchrone sont appelées dans une fonction `async` : la boucle d'événements entière est figée. | Exécution dans le pool de threads (`run_in_threadpool`). |
| B9 | Schéma C vs A | C crée `posts.created`, A attend `posts.created_at`. A ajoute `users.active` et `passkeys.label`. `create_all` n'ajoute **jamais** de colonnes : une base Supabase créée avec C **plante** avec A. | `ensure_schema()` : renommage de `created` en `created_at` et ajout automatique des colonnes manquantes. |
| B10 | C 1904 vs A 209 | Dérivation de clé différente (`user:{id}` vs `agata:user:{id}`) : en passant de C à A, **toutes les clés du coffre deviennent illisibles**. | Déchiffrement compatible avec les deux formats, puis rechiffrement transparent au nouveau format. |
| B11 | C 1846 | Pilote `psycopg2` dans l'URL alors que A utilise `psycopg` (v3) : le pilote ne correspond pas à `requirements.txt`. | `postgresql+psycopg` partout, avec `psycopg[binary]` dans `requirements.txt`. |
| B12 | C 2450 | `PublicKeyCredential.parseCreationOptionsFromJSON` n'existe pas sur les anciens navigateurs : les passkeys plantent. | Fonction native si disponible, sinon conversion manuelle (reprise de A). |
| B13 | C 2422 `feed()` | `?kind=`+k sans encodage. `keys()`, `pend()` et `delKey()` sans gestion d'erreur : promesse rejetée silencieusement. | `encodeURIComponent` partout, wrapper `busy()` avec message d'erreur. |
| B14 | A/C front | Les erreurs de validation Pydantic (liste `detail`) s'affichent « La requête a échoué ». | Le premier message Pydantic est affiché. |
| B15 | C 2445 | Le parseur SSE ignore la dernière trame si le flux se termine sans `\n\n`, et un JSON mal formé casse toute la boucle. | Vidage final du tampon et `try/catch` par trame. |
| B16 | A 1 / C | Modèles par défaut : `claude-3-5-haiku-latest` est ancien, et C utilise `claude-sonnet-5-5` et `gemini-3.5-flash` sans pouvoir les changer par variable d'environnement. | `claude-haiku-4-5`, `gemini-2.5-flash`… tous modifiables via `DEFAULT_*_MODEL`. |
| B17 | Gemini | Les parties « thought » (réflexion) des modèles 2.5 étaient mélangées à la réponse. | Filtrées. |

## 4. Fichiers annexes

| Fichier | Problème | Correction |
|---|---|---|
| `.gitigore` | Faute de frappe : **git l'ignore**, donc `.env` et `agata.db` peuvent être commités. | Renommé `.gitignore`, `.agata_dev_secrets.json` ajouté. |
| `test.smoke.py` | Pytest ne le détecte pas (nom invalide). Il teste `main.safe_url`, `main.enc` et `main.dec`, qui n'existent pas dans A. `/healthz` de A renvoie aussi `service`, donc le test échoue. Base partagée entre exécutions. | `tests/test_smoke.py` : **16 tests** (migration de l'ancien schéma, révocation, CSRF, CSP, SSRF, chiffrement + ancien format, crédits, streaming, votes, pré-détournement OAuth, limitation de débit). |
| `ci-cd.yml` | Pas de `requirements.txt` fourni, donc la CI échoue. Le déploiement se déclenche aussi sur les PR fusionnées sans test. | `requirements.txt` ajouté, `permissions: read`, cache pip, `pip-audit`, déploiement seulement sur push vers `main`. |
| `render.yaml` | IP réelle non configurée. `allkeys-lru` peut évincer les révocations et défis actifs. | `TRUST_PROXY_HOPS=1`, `volatile-lru`, commentaires d'avertissement. |
| `.env.example` | Secrets d'exemple trop courts (refusés en production) et variables manquantes. | Toutes les variables documentées. |

## 5. Nouvelles fonctionnalités

- `/readyz` : vérification de la base et de Redis (en plus de `/healthz`).
- `/api/config` : l'interface n'affiche que les fournisseurs et boutons OAuth réellement configurés, et signale les fournisseurs avec « crédits offerts ».
- Pagination du fil (« Charger plus »), tri « plus votés / plus récents », vote annulable, bouton « Utiliser ce prompt » qui envoie un prompt de la communauté vers le comparateur.
- Bouton « Arrêter » pendant le streaming, notification des remboursements.
- Gestion des passkeys (liste, nom, suppression), changement de mot de passe, « déconnecter tous les appareils ».
- Admin : retrait d'une publication déjà publiée, raison facultative, journal des décisions.
- Messages d'erreur des fournisseurs lisibles (ex. « OpenAI a refusé la requête (HTTP 401) : Incorrect API key… »), avec les secrets masqués.
- CLI : `python main.py promote email`, `python main.py credits email 50`.
- Notifications non bloquantes à la place des `alert()`.

## 6. Vérifications effectuées

- `pytest` : 16/16 réussis.
- `flake8` (erreurs + imports inutilisés) : 0. `bandit -ll` : 0 alerte.
- JavaScript : `node --check` sans erreur.
- Test réel dans Chromium (bureau 1280 px et mobile 390 px) : inscription, publication, comparaison en streaming avec un vrai appel à l'API OpenAI (clé de test refusée en 401, erreur affichée et crédit remboursé), coffre et passkeys. Three.js se charge avec SRI et nonce, sans violation de CSP.

## 7. À faire avant une vraie production

1. Remplacer `ensure_schema()` par des migrations **Alembic** dès que le schéma évolue encore.
2. Ajouter la vérification d'email par lien (inscription par mot de passe) et la réinitialisation du mot de passe.
3. Sauvegardes Supabase automatiques et rotation de `ENCRYPTION_MASTER_KEY` (chiffrement par enveloppe / KMS).
4. Supervision (Sentry, alertes sur `/readyz`).

## 8. Version 3 : e-mails et migrations Alembic

### Vérification d'e-mail et réinitialisation du mot de passe

| Élément | Mise en œuvre |
|---|---|
| Table `email_tokens` | Jetons à usage unique. Seule l'empreinte SHA-256 est stockée, avec une expiration (24 h pour la vérification, 60 min pour la réinitialisation). Un nouveau jeton annule le précédent. |
| Consommation | `UPDATE … WHERE used_at IS NULL AND expires_at > now()` : atomique, impossible à utiliser deux fois, même avec des requêtes simultanées. |
| Envoi | Resend ou Brevo (API HTTPS), car l'offre gratuite de Render bloque le SMTP. SMTP reste disponible pour les offres payantes. Mode `console` en local. Envoi en tâche de fond : le temps de réponse ne révèle pas si un compte existe. |
| Anti-énumération | `/api/password/forgot` renvoie toujours la même réponse et est limité par IP et par adresse. |
| Anti pré-détournement | La vérification exige une session du même compte. La réinitialisation par e-mail révoque les sessions, passkeys et clés d'un compte non vérifié (même logique que pour OAuth, regroupée dans `claim_verified_account`). |
| Admin | `ADMIN_EMAIL` devient admin seulement une fois l'adresse confirmée. |
| Restrictions | `REQUIRE_VERIFIED_EMAIL=1` : publier et utiliser les crédits offerts exigent une adresse confirmée. |
| Interface | Bandeau « Confirmez votre e-mail » avec bouton pour renvoyer le lien, formulaire « Mot de passe oublié », écran « Nouveau mot de passe ». Les jetons sont retirés de l'URL et de l'historique. |
| `.env` | `main.py` charge le fichier `.env` en local (sans dépendance, sans jamais écraser une variable existante). |

### Alembic à la place de `ensure_schema()`

- `0001_baseline` est **idempotente** : elle crée une base vide, met à niveau une base de la version 1 (`posts.created` renommée, colonnes ajoutées) et ne change rien sur une base de la version 2.
- `0002_email_tokens` ajoute la nouvelle table.
- Render : `startCommand: alembic upgrade head && uvicorn …`. En local, `AUTO_MIGRATE=1` applique les migrations au démarrage.
- La CI lance `alembic check`, qui échoue si un modèle a changé sans révision.

### Vérifications

- 23 tests réussis sur SQLite (avec migration d'un ancien schéma) et sur PostgreSQL 18, sous Python 3.11 et 3.14.
- `alembic upgrade`, `downgrade base`, `upgrade` puis `check` : OK.
- Migration d'une base PostgreSQL au schéma v1 avec données : données conservées.
- Démarrage simulé en production avec la `startCommand` Render : `/healthz` OK, HSTS actif, `/docs` désactivé.
- Navigateur : inscription, bandeau, clic sur le lien de confirmation, mot de passe oublié, réinitialisation et reconnexion automatique, sans erreur JavaScript.
