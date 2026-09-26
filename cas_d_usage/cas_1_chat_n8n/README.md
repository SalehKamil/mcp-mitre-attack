# Cas d'usage 1 — Chat MITRE ATT&CK sous n8n

Assistant conversationnel de mapping **MITRE ATT&CK** (Enterprise + ICS). Un
modèle Claude répond aux questions de cybersécurité **en interrogeant le serveur
MCP** plutôt qu'en répondant de mémoire. Son comportement est dicté par un
**skill** — un fichier d'instructions que vous chargez dans n8n. Chaque échange
est journalisé.

```
   Chat (n8n)  ──►  Claude (clé API)  ◄── skill (System Message)
        │
        ├──►  Serveur MCP MITRE   ← version choisie au démarrage
        └──►  log_service.py  ──►  logs.db
```

---

## Contenu de ce dossier

| Fichier | Rôle |
|---|---|
| `setup.py` | Prépare l'installation : vérifications, création de `logs.db` |
| `start.py` | Démarre le serveur MCP (**choix de la version**), la journalisation et n8n |
| `preparer_skill.py` | Transforme vos skills en fichiers prêts à coller dans n8n |
| `log_service.py` | Reçoit les logs de n8n et écrit dans SQLite ; expose `/stats` |
| `schema_logs.sql` | Schéma de la base de journalisation |
| `workflow_mitre_chat.json` | Le workflow à importer dans n8n (skill déjà chargé) |
| `skills_prets/*.txt` | Skills prêts à coller (générés par `preparer_skill.py`) |
| `logs.db` | Base créée par `setup.py` — à ne pas versionner |

**Rien n'est à déplacer.** Les serveurs restent dans `serveur_mcp/`, les skills
dans `github/skills/`. Les scripts remontent l'arborescence pour les trouver :
vous pouvez déplacer ou renommer le projet, rien à reconfigurer.

```
mcp-mitre-attack/
├── serveur_mcp/            v1/  v2/  v3/ …        (inchangé)
├── github/skills/          un dossier par skill    (inchangé)
└── cas_d_usage/cas_1_chat_n8n/   ← ce dossier
```

---

## Prérequis

| Élément | Vérification | Si absent |
|---|---|---|
| Python 3.8+ | `python --version` | <https://python.org> |
| `uv` *(recommandé)* | `uv --version` | facultatif, `python` suffit |
| Node.js LTS (pour n8n) | `node --version` | <https://nodejs.org>, puis rouvrir le terminal |
| Clé API Anthropic | — | <https://console.anthropic.com> (prévoir du crédit) |

---

# Option A — Mise en route par script *(recommandée)*

```powershell
uv run --no-project setup.py          # vérifications + création de logs.db
uv run --no-project preparer_skill.py # prépare les fichiers de skills
uv run --no-project start.py          # choisit la version du serveur, démarre tout
```

`start.py` affiche un menu :

```
  Serveurs disponibles dans ...\serveur_mcp :

    1. v3     v3.0.0   [v3]                  (exige un jeton)
    2. v2-2   v2.2.0   [v2/v2-2]
    3. v2-1   v2.1.0   [v2/v2-1]             (stdio — démarre via le pont HTTP)
    4. v1-1   v1.1.0   [v1/v1-1]             (stdio — démarre via le pont HTTP)

  Serveur a demarrer [1-4, defaut 1] :
```

Il lance le serveur choisi, la journalisation et n8n dans **une seule fenêtre**,
chaque ligne préfixée par son origine (`[MITRE]`, `[LOGS]`, `[N8N]`).
**Ctrl+C arrête l'ensemble.**

Puis, **une seule fois**, dans n8n (<http://localhost:5678>) :

1. créer le compte propriétaire local ;
2. importer `workflow_mitre_chat.json` (menu **…** → *Import from File*) ;
3. nœud **Claude Sonnet** → créer la credential avec votre clé API, puis
   **choisir le modèle dans la liste déroulante** (ne pas le saisir à la main) ;
4. **Save**, puis bouton **Chat**.

### Options de `start.py`

```powershell
uv run --no-project start.py --lister       # lister les serveurs, sans lancer
uv run --no-project start.py --serveur v2-2 # version imposée, sans menu
uv run --no-project start.py --verifier     # tester réellement chaque serveur
uv run --no-project start.py --sans-n8n     # serveur + journalisation seuls
uv run --no-project setup.py --check        # état de l'installation
```

`--verifier` démarre chaque version, l'interroge, l'arrête, et rend un verdict :

```
  Version  Decl.   Transport  Outils  Verdict
  v3       HTTP    natif      14      OK
  v2-2     HTTP    natif      14      OK
  v2-1     stdio   pont       14      OK
  v1-1     stdio   pont       11      OK
```

Les versions sans transport réseau sont servies par un **pont stdio ↔ HTTP**
intégré à `start.py`, qui expose les mêmes routes qu'un serveur HTTP natif :
n8n voit la même interface quelle que soit la version, et **aucun fichier de
serveur n'est modifié**.

---

# Les skills — charger, changer, créer le vôtre

Un skill est un fichier d'instructions qui impose une méthode au modèle
(vérifier avant d'affirmer, ne pas forcer un mapping, citer la version…).

### Charger un skill dans n8n

1. `uv run --no-project preparer_skill.py` — produit un `.txt` par skill dans
   `skills_prets/` ;
2. dans n8n, ouvrir le nœud **AI Agent** ;
3. **Options → System Message** ;
4. coller le contenu du fichier voulu ;
5. **Save**.

Changer de skill = coller un autre fichier.

### Créer le vôtre

Créez un dossier dans `github/skills/` :

```
github/skills/mon-skill/
├── SKILL.md              obligatoire
└── references/           facultatif
    └── ma-methode.md
```

Relancez `preparer_skill.py` : `skills_prets/mon-skill.txt` apparaît, prêt à
coller.

### Ce que `preparer_skill.py` fait pour vous

Il ne recopie pas le fichier tel quel. Il fusionne le `SKILL.md` et ses
références en un seul texte — n8n n'ayant pas de chargement progressif, un
renvoi vers un autre fichier y serait une instruction impossible à suivre. Il
retire l'en-tête YAML, corrige les noms d'outils périmés
(`mitre_status` → `mitre_stats`, `search_datasources` → `get_datasources`),
supprime les mentions d'outils inexistants, et ajoute en tête la liste des
outils réellement exposés par votre serveur.

Il signale enfin les outils qu'un skill réclame mais que le serveur n'expose
pas. Cas réel : le skill CTI exige `list_internal_techniques`,
`search_internal` et `get_internal_technique`, apparus en **v2.1**. Il ne peut
donc pas fonctionner avec la v1.1.

| Skill | v1.1 | v2.1 | v2.2 | v3.x |
|---|:--:|:--:|:--:|:--:|
| mitre-attack-assistant | oui | oui | oui | oui |
| assistant-mitre-cti | **non** | oui | oui | oui |

---

# Option B — Procédure manuelle

Si vous préférez tout contrôler, ou en cas d'échec d'un script.

### B.1 — Créer la base

```powershell
uv run --no-project python -c "import sqlite3;con=sqlite3.connect('logs.db');con.executescript(open('schema_logs.sql',encoding='utf-8').read());con.commit();con.close();print('logs.db creee')"
```

*(`sqlite3.exe` n'est pas fourni avec Windows ; Python embarque SQLite.)*

### B.2 — Serveur MCP — **fenêtre 1**

Depuis le dossier de la version voulue :

```powershell
cd ..\..\serveur_mcp\v2\v2-2
uv run --no-project mcp_mitre.py --http
```

Avec la **v3**, définir d'abord un jeton, sinon le démarrage est refusé :

```powershell
$env:MCP_HTTP_TOKEN="mon-jeton-de-demo"
```

Les versions **antérieures à la v2-2 n'ont pas de mode HTTP** : en manuel, elles
ne conviennent qu'à Claude Code (stdio). Pour n8n, passez par `start.py`, qui
fournit le pont.

### B.3 — Journalisation — **fenêtre 2**

```powershell
uv run --no-project log_service.py
```

### B.4 — n8n — **fenêtre 3**

```powershell
npx n8n
```

Puis <http://localhost:5678> et les quatre points de l'option A.

---

## Vérifier que tout fonctionne

Dans le chat :

```
Un attaquant a extrait la mémoire du processus lsass.exe avec comsvcs.dll.
Quelle technique ATT&CK correspond ?
```

Trois signes :

1. la réponse cite **T1003.001** et rappelle la release ATT&CK consultée ;
2. la fenêtre du serveur montre les appels d'outils au moment de la question ;
3. `Invoke-RestMethod http://127.0.0.1:8790/stats` compte un tour de plus.

### La mesure qui compte

`mcp_used` vaut `1` si le modèle a réellement interrogé le serveur, `0` s'il a
répondu de lui-même :

```sql
SELECT ROUND(100.0 * SUM(mcp_used) / COUNT(*), 1) AS taux_ancrage_pct
FROM executions;
```

Un `0` n'est pas un défaut d'installation : c'est un **résultat** à analyser.

---

## Dépannage

| Symptôme | Cause | Solution |
|---|---|---|
| `serveur_mcp introuvable` | Arborescence différente | `--serveurs-dir "..\..\serveur_mcp"` |
| `MODE HTTP REFUSE : aucune authentification` | Version durcie (v3) sans jeton | `start.py` en génère un ; sinon définir `MCP_HTTP_TOKEN` |
| n8n : *connection refused* sur MCP | Serveur non démarré ou mauvais port | Tester `http://127.0.0.1:8733/healthz` |
| Nœud MCP en boucle | Bug de transport de certaines versions de n8n | Passer le nœud en *SSE*, URL `http://127.0.0.1:8733/sse` |
| Claude : erreur 401 | Clé API invalide | Recréer la credential, vérifier les espaces |
| Claude : *model not found* | Modèle saisi à la main | Le choisir dans la liste déroulante |
| `sqlite: database is locked` | Dossier synchronisé (Drive/OneDrive) | Copier le projet sur un disque local |
| `npx` non reconnu | Node.js absent ou terminal non rouvert | Installer Node.js LTS puis **rouvrir** le terminal |
| Le modèle ignore la méthode | Skill non chargé | Vérifier *System Message* du nœud AI Agent |
| Port déjà utilisé | Instance restée ouverte | Fermer l'autre fenêtre, ou `MCP_HTTP_PORT` / `LOG_PORT` |

---

## Note de périmètre

Le serveur est exposé en HTTP **sans authentification** sur la boucle locale
(sauf la v3, qui impose un jeton). C'est volontaire pour la démonstration. Le
durcissement complet — TLS, limitation de débit, garde Origin — relève du jalon
production.
