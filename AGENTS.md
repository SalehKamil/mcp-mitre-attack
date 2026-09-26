# Dépôt : serveur MCP MITRE ATT&CK

Ce dépôt contient la lignée d'un serveur MCP (Python, **bibliothèque
standard uniquement** : ni `pip`, ni `uv`) exposant la base MITRE ATT&CK
**Enterprise + ICS** à un agent IA, complétée à partir de la v2.1 d'un
référentiel interne de fiches `THQxxxx` (lecture seule). Chaque version vit
dans son propre dossier de `serveur_mcp/`, réduite à un seul fichier
`mcp_mitre.py` (les bundles STIX sont téléchargés au premier lancement) :

| Version | Dossier | Périmètre |
|---|---|---|
| 1.0 | `serveur_mcp/v1/v-1-0` | Enterprise seul, 11 outils `mitre_*` |
| 1.1 | `serveur_mcp/v1/v-1-1` | Enterprise + ICS, 11 outils `get_*` |
| 2.0 | `serveur_mcp/v2/v2-0` | moteur réécrit : recherche scorée, redirections des révoquées, détections v18/v19 |
| 2.1 | `serveur_mcp/v2/v2-1` | + référentiel interne THQ (14 outils) |
| 2.2 | `serveur_mcp/v2/v2-2` | + mode `--http` local **sans** authentification |
| 3.0 | `serveur_mcp/v3/v3_0` | + HTTP sans état, Bearer obligatoire |
| 3.1.0 | `serveur_mcp/v3/v3_0` | + portées, OAuth 2.1, gardes réseau, audit chaîné — **version de référence** |

Sauf mention contraire, « le serveur » désigne
`serveur_mcp/v3/v3_0/mcp_mitre.py`. Chaque dossier est un jalon figé de la
lignée : ne pas rétro-porter dans une version une fonctionnalité ou un
durcissement documenté comme apport d'une version ultérieure (voir le
`README.md` / `RELEASE_NOTES*.md` de chaque dossier).

## Démarrage (mode local stdio — VS Code)

Dans `serveur_mcp/v3/v3_0/`, dans l'ordre :

1. Rien à installer : Python 3.10+ suffit (le fichier utilise `dict | None`),
   aucune dépendance.
2. Lancer : `uv run mcp_mitre.py` (aucun jeton requis en stdio). Au premier
   lancement, le serveur télécharge les bundles `attack-stix-data` dans
   `MITRE_DB/` (~57 Mo) et journalise dans `Logs/` — les deux **à côté de
   `mcp_mitre.py`**, ou dans `MCP_DATA_DIR` si cette variable est définie.
3. Vérifier : `uv run mcp_mitre.py --test` (statistiques de chargement,
   liste des 14 outils, empreinte SHA-256 du manifeste d'outils).

`.vscode/mcp.json` déclare ce serveur sous le nom `mitre-attack` (stdio,
chemin relatif à la racine du dépôt). Le référentiel interne est lu dans
`referentiel_interne.json` à côté du fichier (ou `MCP_INTERNAL_DB`) ; sans
ce fichier, le serveur démarre avec 0 fiche.

## Outils exposés par le serveur MCP (14)

Base ATT&CK (portée `mitre.read`) : `get_tactics()`, `get_tactic(id)`,
`get_technique(id)`, `get_mitigation(id)`, `get_groups(technique_id?)`,
`get_group(id)`, `get_software(technique_id?)`, `get_datasources(query)`,
`search_techniques(query, limit?, matrix?, platform?, tactic?)`,
`mitre_stats()`.

Référentiel interne (portée `internal.read`) : `list_internal_techniques()`,
`get_internal_technique(id)`, `search_internal(query, limit?)`.

Administration (portée `admin`) : `mitre_update()` — jamais en routine.

Noms et formats de sortie inchangés depuis la v2.1 ; les portées ne
s'appliquent qu'en HTTP (en stdio, tout est accessible). Les v1.x exposent
d'autres noms (`mitre_*` en v1.0) — consulter leur README.

**Interdit : ne jamais appeler `get_run_metrics`** (réservé à la
journalisation des workflows n8n ; ce n'est pas un outil du serveur).

## Méthode de travail

- Avant toute tâche ATT&CK, consulter le skill `mitre-attack-assistant`
  (`.github/skills/mitre-attack-assistant/SKILL.md`) : il définit le triage
  des demandes, la méthode et les formats de sortie. Pour l'analyse complète
  d'un rapport CTI avec proposition de fiches internes THQ, utiliser le skill
  `assistant-mitre-cti` (`.github/skills/mitre-attack-assistant-CTI/`) s'il
  est installé.
- Principe « **proposer puis vérifier** » : `search_techniques` (mots-clés
  anglais, une requête = un comportement atomique ; score normalisé [0..1],
  ≥ 0,6 candidat fort, < 0,3 faible) puis `get_technique` pour confirmer
  chaque candidat retenu. Technique parente par défaut, sous-technique
  seulement si l'entrée le prouve.
- Ne jamais inventer d'identifiant ATT&CK ni THQ ; « non trouvé » (ou une
  liste vide) est une réponse valide. Un identifiant révoqué est redirigé
  vers son remplaçant (`redirect`) : citer le remplaçant.
- Avant de proposer une fiche THQ : `list_internal_techniques` (prochain id
  libre) puis `search_internal` (anti-doublon). Le référentiel est en lecture
  seule : livrer un brouillon JSON, jamais écrire dans
  `referentiel_interne.json`.
- Citer la version de la base (`mitre_stats` → `db_version`, une fois par
  conversation) dans tout mapping.

## Tests

Harnais dans `serveur_mcp/tests/` (bibliothèque standard ; chaque harnais
lance le serveur en sous-processus — aucun téléchargement si le `MITRE_DB/`
de la version est déjà présent). Depuis `serveur_mcp/` :

```bash
uv run tests/test_stdio.py v3/v3_0 v3.1.0                    # 27 scénarios stdio JSON-RPC
uv run tests/test_http.py  v3/v3_0 v3.1.0 8743 scopes full   # Bearer + portées
uv run tests/test_http.py  v3/v3_0   v3.0   8742 bearer full
uv run tests/test_http.py  v2/v2-2   v2.2   8741 noauth full
```

Les réponses complètes sont écrites dans `serveur_mcp/tests/resultats/`
(ignoré par git). Rapport de la dernière campagne :
`serveur_mcp/tests/RAPPORT_TESTS_2026-09-05.md`. Le serveur seul se vérifie
par `uv run mcp_mitre.py --test` ; `--manifest`, `--fingerprints` et
`--verify-audit <journal>` couvrent l'intégrité (v3.1.0).

## Sécurité

- Le mode stdio (VS Code) ne transite pas par le réseau : aucune
  authentification requise.
- Toute exposition **hors VS Code** se fait par `uv run mcp_mitre.py --http`
  avec authentification **obligatoire** : `MCP_HTTP_TOKEN` (jeton unique,
  16 caractères minimum ; portées via `MCP_HTTP_TOKEN_SCOPES`, par défaut
  `mitre.read,internal.read` **sans** `admin`) ou `MCP_TOKENS`
  (`nom:jeton:portées;…`), et/ou OAuth 2.1 par introspection
  (`MCP_AUTH_MODE=oauth`, `MCP_RESOURCE_URI`, `MCP_OAUTH_INTROSPECTION_URL`,
  `MCP_OAUTH_ISSUER`). Le serveur applique le principe fail-closed et refuse
  de démarrer sans mécanisme configuré, avec un jeton trop court, ou en
  clair hors loopback : `--host 0.0.0.0` exige `--tls-cert`/`--tls-key` (ou
  `MCP_TRUST_PROXY=1` derrière un reverse proxy qui termine TLS).
- Secrets uniquement via variables d'environnement, `MCP_HTTP_TOKEN_FILE`,
  ou un `.env` non versionné (le dépôt ne fournit pas de `.env.example` ;
  sous VS Code, utiliser le champ `envFile` de `mcp.json`).
- Ne jamais committer : `.env`, `MITRE_DB/`, `Logs/` (dont
  `mcp_audit.jsonl`), `resultats/` — tous déjà dans `.gitignore`.
