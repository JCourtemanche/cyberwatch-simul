# Cyberwatch API Simulator

Simulateur de l'API Cyberwatch (Vulnerability & Compliance Manager) pour tester et démontrer l'intégration **Cyberwatch (Partner Contribution)** dans Cortex XSIAM sans avoir accès à une instance Cyberwatch réelle.

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template) et le package partagé [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) pour que les mêmes utilisateurs, hôtes et IPs Business Corp apparaissent de manière cohérente à travers tous les simulateurs.

## Contexte

Ce projet simule les endpoints REST utilisés par l'intégration Cortex XSIAM Cyberwatch (fichier `Integrations/integration-Cyberwatch.yml` dans le pack marketplace). Il implémente toutes les commandes du pack — CVEs, assets (vulnerabilities / sysadmin / compliance), security issues, declarative data, ping — de sorte que l'intégration puisse être configurée, testée et faire fetcher des incidents comme si elle parlait à un vrai master scanner Cyberwatch.

## Endpoints simulés

Toutes les routes utilisent **HTTP Basic Auth** (nom d'utilisateur = API access key, mot de passe = API secret key).

### Health & auth
- `GET /health` — santé du simulateur (pas d'auth)
- `GET /api/v3/ping` — utilisé par `test-module` de l'intégration

### CVEs — `/api/v3/vulnerabilities/cve_announcements`
- `GET /api/v3/vulnerabilities/cve_announcements` — liste paginée
  - filtres : `level`, `active`, `ignored`, `prioritized`, `exploit_code_maturity[]`, `access_vector[]`, `technology_vendor`, `technology_product`, `page`, `per_page`
- `GET /api/v3/vulnerabilities/cve_announcements/<cve_code>` — détail (avec `servers`, `security_announcements`, `references`)

### Assets — vue Vulnerabilities — `/api/v3/vulnerabilities/servers`
- `GET /api/v3/vulnerabilities/servers` — liste paginée
  - filtres : `environment_id`, `reboot_required`, `os`, `group_id`, `hostname`, `address`, `category`, `communication_failed`, `page`, `per_page`
- `GET /api/v3/vulnerabilities/servers/<id>` — détail complet (avec `cve_announcements[]`, `security_issues[]`, `updates[]`, `groups`, `compliance_repositories`, `environment`)

### Assets — vue Sysadmin — `/api/v3/assets/servers`
- `GET /api/v3/assets/servers` — liste
- `GET /api/v3/assets/servers/<id>` — détail (avec `policy_id`, `deploying_period_id`, `rebooting_period_id`, `ignoring_policy_id`)

### Assets — vue Compliance
- `GET /api/v3/compliance/assets` — liste
- `GET /api/v3/compliance/servers/<id>` — détail (avec `compliance_rules_count`, `compliance_rules_failed_count`, `compliance_repositories`)

### Security Issues — `/api/v3/security_issues`
- `GET /api/v3/security_issues` — liste paginée (filtres : `level`, `sid`)
- `GET /api/v3/security_issues/<id>` — détail (avec `servers`, `servers_count`, `cve_announcements_count`)

### Declarative Data (airgap scan uploads)
- `POST /api/v2/cbw_scans/scripts` — upload d'un blob déclaratif
- `GET /api/v3/servers/<id>/info` — lecture du blob (retourne du texte brut)

### Pagination
Les endpoints de liste renvoient les en-têtes attendus par le client de l'intégration :
- `x-page`, `x-per-page`, `x-total`, `x-total-pages`

## Correspondance avec les commandes XSIAM

| Commande XSIAM | Endpoint simulé |
|---|---|
| `test-module` | `GET /api/v3/ping` |
| `cyberwatch-list-cves` | `GET /api/v3/vulnerabilities/cve_announcements` |
| `cyberwatch-fetch-cve` | `GET /api/v3/vulnerabilities/cve_announcements/<cve_code>` |
| `cyberwatch-list-assets` | `GET /api/v3/vulnerabilities/servers` |
| `cyberwatch-fetch-asset` | `GET /api/v3/vulnerabilities/servers/<id>` |
| `cyberwatch-fetch-asset-fulldetails` | `GET /api/v3/vulnerabilities/servers/<id>` |
| `cyberwatch-list-securityissues` | `GET /api/v3/security_issues` |
| `cyberwatch-fetch-securityissue` | `GET /api/v3/security_issues/<id>` |
| `cyberwatch-list-sysadmin-assets` | `GET /api/v3/assets/servers` |
| `cyberwatch-fetch-sysadmin-asset` | `GET /api/v3/assets/servers/<id>` |
| `cyberwatch-list-compliance-assets` | `GET /api/v3/compliance/assets` |
| `cyberwatch-fetch-compliance-asset` | `GET /api/v3/compliance/servers/<id>` |
| `cyberwatch-send-declarative-data-asset` | `POST /api/v2/cbw_scans/scripts` |
| `cyberwatch-get-declarative-data-asset` | `GET /api/v3/servers/<id>/info` |
| `fetch-incidents` | s'appuie sur `list_assets` + `fetch_asset` pour dériver un incident par CVE détectée |

## Dataset

- **40 CVEs** réelles (Log4Shell, ProxyLogon, PrintNightmare, MOVEit, Follina, Spring4Shell, Zerologon, EternalBlue, regreSSHion, PAN-OS 2024, etc.) avec CVSS v3, EPSS, exploit maturity, technologies, CWE
- **~18 assets** : les 6 personas Business Corp (Alice, Bob, Charlie, David, Emma, Flora) + 12 serveurs générés (web, db, mail, AD, VPN, monitoring, CI, ESXi, NAS)
- **15 security issues** (pentests, TLS obsolète, SSH root, SMBv1, CIS, ANSSI…)
- Chaque asset a une sous-sélection stable de CVEs et security issues, ainsi que des `updates[]` (patches) qui référencent les CVEs à corriger

Les IDs, dates et affectations sont générés avec un seed déterministe : deux exécutions du simulateur produisent exactement les mêmes réponses.

## Installation locale

### Prérequis
- Python 3.11+

### Lancement

```bash
cd simulator
pip install -r requirements.txt
python app.py
# → http://localhost:8080
```

### Tests rapides

```bash
# Health (sans auth)
curl http://localhost:8080/health

# Ping (auth)
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  http://localhost:8080/api/v3/ping

# Liste des CVEs critiques
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  "http://localhost:8080/api/v3/vulnerabilities/cve_announcements?level=level_critical&per_page=5"

# Liste des assets
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  "http://localhost:8080/api/v3/vulnerabilities/servers?per_page=5"

# Détail complet d'un asset
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  "http://localhost:8080/api/v3/vulnerabilities/servers/900"

# Security issues
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  "http://localhost:8080/api/v3/security_issues"

# Declarative data d'un serveur
curl -u cyberwatch-access-key:cyberwatch-secret-key \
  "http://localhost:8080/api/v3/servers/900/info"
```

## Déploiement sur GCP Cloud Run

```bash
bash deploy-cloudrun.sh
```

Le script :
1. Active les APIs (`run`, `cloudbuild`, `artifactregistry`)
2. Crée le repository Artifact Registry `cyberwatch-simulator`
3. Build l'image Docker via `gcloud builds submit --config cloudbuild.yaml`
4. Déploie sur Cloud Run (`europe-west1`, service `cyberwatch-simulator`, mémoire 512Mi)
5. Rend le service public (`allUsers` → `roles/run.invoker`)

Pour personnaliser les credentials :
```bash
CW_ACCESS_KEY="my-access-key" CW_SECRET_KEY="my-secret-key" bash deploy-cloudrun.sh
```

## Configuration dans XSIAM

Dans **Settings → Integrations → Cyberwatch (Partner Contribution)** :

| Paramètre | Valeur |
|---|---|
| Master scanner URL | `https://cyberwatch-simulator-<hash>-ew.a.run.app` (URL Cloud Run) |
| API Access key | `cyberwatch-access-key` (ou celle passée à `deploy-cloudrun.sh`) |
| API Secret key | `cyberwatch-secret-key` (ou celle passée à `deploy-cloudrun.sh`) |
| Trust any certificate | Non (Cloud Run fournit un cert valide) |
| First fetch time | `3 days` |
| Fetch Limit | `50` |
| Asset filters (JSON) | `{}` |
| CVE filters (JSON) | `{"active": true, "ignored": false, "prioritized": true}` |

Cliquer sur **Test** — l'intégration appelle `GET /api/v3/ping` et doit renvoyer `ok`.

## Structure du projet

```
cyberwatch-simul/
├── README.md
├── cloudbuild.yaml
├── deploy-cloudrun.sh
├── deployment/
│   ├── Dockerfile
│   └── app.yaml
└── simulator/
    ├── app.py               # Flask app factory + blueprint registration
    ├── auth.py              # HTTP Basic Auth (access_key / secret_key)
    ├── config.py            # env vars: keys, pagination, dataset sizes
    ├── requirements.txt
    ├── generators/
    │   ├── base.py          # personas + OS catalog + groups + environments
    │   ├── cves.py          # 40-CVE catalog (Log4Shell, ProxyLogon, …)
    │   ├── security_issues.py
    │   ├── assets.py        # persona + serveurs générés + updates
    │   └── catalog.py       # instantiation unique du dataset
    └── routes/
        ├── _helpers.py      # pagination
        ├── ping.py
        ├── cves.py
        ├── assets.py        # /vulnerabilities/servers
        ├── sysadmin.py      # /assets/servers
        ├── compliance.py    # /compliance/assets, /compliance/servers/<id>
        ├── security_issues.py
        └── declarative.py   # /api/v2/cbw_scans/scripts, /api/v3/servers/<id>/info
```

## Personas partagés — Business Corp

Ces données viennent du package [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) et sont identiques dans tous les simulateurs.

| Utilisateur | Email | Hostname | IP | OS |
|---|---|---|---|---|
| Alice Dupont | alice.dupont@business.org | BSNS-WIN-ALICE | 192.168.1.1 | Windows 10 Pro |
| Bob Martin | bob.martin@business.org | BSNS-MAC-BOB | 192.168.1.2 | macOS 13 Ventura |
| Charlie Durant | charlie.durant@business.org | BSNS-WIN-CHARLIE | 192.168.1.3 | Windows 11 Pro |
| David Lefebvre | david.lefebvre@business.org | BSNS-WIN-DAVID | 192.168.1.4 | Windows 10 Pro |
| Emma Leroy | emma.leroy@business.org | BSNS-MAC-EMMA | 192.168.1.5 | macOS 14 Sonoma |
| Flora Moreau | flora.moreau@business.org | BSNS-MOB-FLORA | 192.168.1.6 | iOS 17 |

## Simulateurs frères

| Projet | API simulée |
|---|---|
| [proofpoint-tap-simulator](https://github.com/JCourtemanche/proofpoint-tap-simulator) | ProofPoint TAP |
| [sentinelone-simul](https://github.com/JCourtemanche/sentinelone-simul) | SentinelOne |
| [cato-networks-simul](https://github.com/JCourtemanche/cato-networks-simul) | Cato Networks |
| [cyberwatch-simul](https://github.com/JCourtemanche/cyberwatch-simul) | Cyberwatch (Framatome) |
