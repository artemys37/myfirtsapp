# NetAudit

Plateforme web de découverte réseau et d'audit de sécurité.  
Interface SPA moderne (Tailwind CSS) + API REST (FastAPI / Python) + MongoDB.

---

## Architecture

```
myfirtsapp/
├── backend/                  # API FastAPI (Python 3.12)
│   ├── Dockerfile            # Image multi-stage (slim + outils)
│   ├── requirements.txt
│   └── app/
│       ├── main.py           # Point d'entrée FastAPI
│       ├── config.py         # Configuration MongoDB / JWT
│       ├── db.py             # Connexion MongoDB (motor)
│       ├── schemas.py        # Modèles Pydantic
│       └── routers/
│           ├── scan.py       # Scan réseau (nmap)
│           ├── vulns.py      # Détection de vulnérabilités (synthétiques CVE)
│           ├── auth.py       # Authentification JWT
│           ├── auth_test.py  # Tests de bruteforce (SSH, FTP, SMB, RDP, Telnet)
│           ├── sqli.py       # Détection d'injections SQL (sqlmap)
│           ├── tools.py      # Catalogue d'outils + exécution
│           ├── terminal.py   # Terminal WebSocket (SSH / Telnet)
│           ├── wifi.py       # Scan WiFi et extraction de mots de passe
│           ├── reports.py    # Génération de rapports
│           └── integration.py# Endpoints de synchronisation
├── frontend/
│   ├── index.html            # Single Page Application (Tailwind CSS)
│   └── nginx.conf            # Configuration Nginx
├── infra/
│   └── init.d/
│       └── mongo-init.js     # Initialisation MongoDB
└── docker-compose.yml
```

---

## Déploiement

### Prérequis

- Docker 24+ et Docker Compose v2
- 4 Go de RAM minimum
- 10 Go d'espace disque

### Variables d'environnement

Copier `.env.example` (ou définir dans l'environnement) :

| Variable | Défaut | Description |
|---|---|---|
| `MONGO_USER` | `admin` | Utilisateur MongoDB |
| `MONGO_PASSWORD` | `secret` | Mot de passe MongoDB |
| `JWT_SECRET` | *(auto-généré)* | Clé de signature JWT |
| `NVD_API_KEY` | *(optionnel)* | Clé API NVD pour CVEs réelles |

### Lancement

```bash
docker compose up -d
```

Accès :
- **Frontend** : http://localhost:80 → redirige vers https://localhost:443
- **API** : https://localhost:443/api/ (Swagger : https://localhost:443/docs)
- **Mongo Express** : http://localhost:8081 (profil `debug`)

### HTTPS (auto-signé)

Un certificat auto-signé est généré lors du premier déploiement.  
Le serveur écoute sur les ports **80** (redirection → HTTPS) et **443** (HTTPS).

> **Note iOS** : Safari affichera un avertissement "Ce certificat n'est pas valide".  
> Appuyez sur **"Afficher les détails"** → **"Visiter ce site web"** pour procéder.  
> Le terminal WebSocket (wss://) fonctionnera après avoir accepté le certificat.

### Build sans Docker Hub

Si Docker Hub est inaccessible, les images sont construites localement :

```bash
docker compose build --pull=false
```

L'image `python:3.12-slim` est utilisée comme base ; les binaires d'outils additionnels sont téléchargés depuis GitHub Releases.

---

## Fonctionnalités

### Scan réseau
- Découverte de sous-réseaux (nmap)
- Détection de ports ouverts, services, versions, bannières
- Historique des campagnes de scan

### Vulnérabilités
- Cartographie CVE par service détecté (SSH, HTTP, FTP, SMB, RDP, MySQL, PostgreSQL, MongoDB, Redis, DNS, SMTP, SNMP)
- Scores CVSS, sévérités (CRITIQUE → INFO)
- Liens cliquables vers NVD
- Fallback synthétique quand l'API NVD est injoignable
- Mapping MITRE ATT&CK

### Tests d'authentification
- Bruteforce SSH, FTP, SMB, RDP, Telnet
- Support de wordlists (rockyou.txt intégré : 14M mots)
- Ouverture de terminal WebSocket SSH/Telnet sur succès
- Compatible PuTTY (infos de connexion affichées)

### Injection SQL
- Scan automatisé avec sqlmap
- Détection de techniques (B, E, U, S, T, Q)
- Polling asynchrone des résultats

### Catalogue d'outils
14 outils de sécurité avec interface interactive :

| Outil | Statut | Description |
|---|---|---|
| **Nmap** | ✅ Installé | Scan de ports et détection de services |
| **Nikto** | ✅ Installé | Scan de vulnérabilités web |
| **Gobuster** | ✅ Installé | Bruteforce de répertoires web |
| **Hashcat** | ⚠️ Fallback Python | Craquage de hash (GPU non disponible) |
| **John** | ⚠️ Fallback Python | Craquage de hash |
| **Hydra** | 🔀 Redirection Auth | Bruteforce de mots de passe |
| **7-Zip** | ✅ Installé | Test d'archives protégées |
| **SQLmap** | ✅ Installé | Détection d'injections SQL |
| **DIRB** | ✅ Installé | Scan de répertoires web |
| **Aircrack-ng** | ✅ Installé | Suite d'audit WiFi |
| **TShark** | ✅ Installé | Analyse de capture réseau |
| **Wifite** | ✅ Installé | Audit WiFi automatisé |
| **Burp Suite** | 📖 Référence | Proxy d'interception web |
| **OpenVAS** | 📖 Référence | Scanner de vulnérabilités |
| **Nessus** | 📖 Référence | Scanner de vulnérabilités |
| **Kismet** | ❌ Non disponible | Détection réseau sans fil |

### Terminal WebSocket
- Connexion SSH/Telnet interactive dans le navigateur (xterm.js)
- Informations de connexion affichées pour utilisation avec PuTTY

### WiFi
- Détection des réseaux sans fil
- Extraction des mots de passe sauvegardés (Linux)

### Rapports
- Génération au format JSON / CSV
- Inclusion des vulnérabilités, tests d'auth, mapping MITRE

---

## API

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/health` | Healthcheck |
| `POST` | `/api/auth/login` | Authentification |
| `POST` | `/api/scan/run` | Lancer un scan réseau |
| `GET` | `/api/scan/:id` | Résultats d'un scan |
| `DELETE` | `/api/scan/:id` | Supprimer un scan |
| `GET` | `/api/vulns/:scan_id` | Vulnérabilités d'un scan |
| `POST` | `/api/auth-test/run` | Lancer un test d'auth |
| `GET` | `/api/auth-test/wordlist-sample` | Échantillon rockyou.txt |
| `GET` | `/api/auth-test/:scan_id` | Résultats des tests d'auth |
| `POST` | `/api/sqli/run` | Lancer un scan SQLi |
| `GET` | `/api/sqli/:id` | Statut d'un scan SQLi |
| `GET` | `/api/tools/check` | Statut des outils installés |
| `POST` | `/api/tools/:id/run` | Exécuter un outil |
| `GET` | `/api/tools/wordlists` | Chemins des wordlists disponibles |
| `WS` | `/api/terminal/ws` | Terminal WebSocket |
| `GET` | `/api/wifi/status` | Statut matériel WiFi |
| `GET` | `/api/reports/generate` | Générer un rapport |

Documentation interactive : http://localhost:8000/docs

---

## Wordlists

Le fichier `rockyou.txt` (14 344 391 mots, 134 Mo) est pré-installé dans `/usr/share/wordlists/`.

Autres wordlists disponibles :
- `/usr/share/dirb/wordlists/common.txt` (4 614 entrées)
- `/usr/share/dirb/wordlists/big.txt` (20 458 entrées)
- `/usr/share/nmap/nmap-services` (9 000+ signatures)

---

## Bonnes pratiques

- Utiliser des campagnes de scan avec `scan_id` pour organiser les résultats
- Les tests d'authentification ne doivent être lancés que sur des systèmes autorisés
- Le terminal WebSocket expire après 5 minutes d'inactivité
- Les rapports peuvent être exportés pour archivage ou conformité

---

## Dépannage

**Erreur : `No OpenCL platform found` (hashcat)**  
→ Hashcat nécessite un GPU et OpenCL. Utiliser le fallback Python intégré.

**Erreur : `docker: no matching manifest for linux/amd64`**  
→ Vérifier l'architecture du serveur hôte.

**Erreur : `TLS timeout` sur Docker Hub**  
→ Build local avec `docker compose build --pull=false`.

**Le scan réseau ne retourne aucun résultat**  
→ Vérifier que la cible est accessible depuis le conteneur :  
`docker exec netaudit_backend ping <cible>`
