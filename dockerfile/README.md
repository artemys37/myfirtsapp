# NetAudit 🛡️

Plateforme de reconnaissance réseau et d'audit de sécurité.

## Stack

| Couche | Technologie |
|---|---|
| Backend | Python 3.12 + FastAPI |
| Base de données | MongoDB 7.0 |
| Frontend | HTML + Tailwind CSS (Nginx) |
| Orchestration | Docker Compose |

---

## 🚀 Démarrage rapide

### Prérequis

- Docker ≥ 24
- Docker Compose ≥ 2.20
- `make` (optionnel)

### 1. Cloner et configurer

```bash
git clone <repo>
cd netaudit
cp .env.example .env
# Éditez .env pour changer les mots de passe
```

### 2. Lancer

```bash
make up
# ou sans make :
docker compose up -d --build
```

### 3. Accéder

| Service | URL |
|---|---|
| Frontend | http://localhost |
| API (Swagger) | http://localhost:8000/docs |
| API (ReDoc) | http://localhost:8000/redoc |
| MongoDB (debug) | http://localhost:8081 |

---

## 📋 Commandes utiles

```bash
make up           # Démarrer
make down         # Arrêter
make debug        # Démarrer + Mongo Express UI
make logs         # Suivre les logs
make shell-backend  # Shell dans le backend
make shell-mongo    # Shell MongoDB
make clean        # Supprimer tout (données incluses)
make reset        # Clean + rebuild
```

---

## 🔑 Variables d'environnement (.env)

| Variable | Description | Défaut |
|---|---|---|
| `MONGO_USER` | Utilisateur root MongoDB | `admin` |
| `MONGO_PASSWORD` | Mot de passe MongoDB | `changeme` |
| `MONGO_DB` | Nom de la base | `netaudit` |
| `SECRET_KEY` | Clé JWT backend | à changer |

---

## 📡 API Endpoints

### Scan
| Méthode | Route | Description |
|---|---|---|
| POST | `/api/scan/start` | Lancer un scan |
| GET | `/api/scan/` | Lister les campagnes |
| GET | `/api/scan/{id}` | Statut d'un scan |
| GET | `/api/scan/{id}/hosts` | Hôtes découverts |

### Vulnérabilités
| Méthode | Route | Description |
|---|---|---|
| POST | `/api/vulns/analyze/{scan_id}` | Analyser CVE + MITRE |
| GET | `/api/vulns/{scan_id}` | Lister les vulnérabilités |
| GET | `/api/vulns/{scan_id}/mitre` | Mapping MITRE ATT&CK |

### Auth Tests
| Méthode | Route | Description |
|---|---|---|
| POST | `/api/auth-test/run` | Lancer les tests d'auth |
| GET | `/api/auth-test/{scan_id}` | Résultats |

### Rapports
| Méthode | Route | Description |
|---|---|---|
| POST | `/api/reports/generate` | Générer (JSON/CSV/PDF) |
| GET | `/api/reports/{scan_id}` | Rapports existants |

---

## ⚠️ Avertissement légal

Cette plateforme est destinée **exclusivement** aux audits de sécurité autorisés.
Toute utilisation sur des systèmes sans autorisation explicite est illégale.

---

## 📁 Structure du projet

```
netaudit/
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── models/schemas.py
│   ├── routers/
│   │   ├── scan.py
│   │   ├── vulns.py
│   │   ├── auth_test.py
│   │   └── reports.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   └── nginx.conf
├── infra/
│   └── mongo-init.js
├── docker-compose.yml
├── Makefile
├── .env.example
└── README.md
```
