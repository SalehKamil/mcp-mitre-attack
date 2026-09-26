# Serveur MCP MITRE ATT&CK — Hybride Enterprise + ICS + référentiel interne (v2.2)

Serveur MCP qui expose à un modèle de langage une base de connaissance MITRE
ATT&CK **hybride Enterprise (IT) et ICS (OT)**, étendue par un **référentiel
interne de techniques** propre à l'organisation (fiches `THQxxxx`). Il est
conçu pour du **mapping TTP de haute précision** selon la méthode *proposer
puis vérifier* : `search_techniques` propose des candidats scorés avec preuves,
`get_technique` confirme chaque candidat, `search_internal` confronte le
résultat au référentiel maison.

La v2.2 lit en plus les objets qu'ATT&CK publie et que le serveur ignorait
jusqu'ici : les **campagnes** (`get_campaign`), qui portent une part
importante des techniques d'un groupe, les **équipements industriels**
(`get_asset`) visés par les techniques ICS, et les **techniques dépréciées**,
désormais signalées comme telles au lieu d'être confondues avec un identifiant
inexistant. La recherche a été refondue : nom de la technique parente,
acronymes, pondération par rareté, entités nommées et tactiques comme indices.

Le référentiel interne est une **extension de MITRE, jamais un remplacement** :
une fiche n'existe que si ATT&CK ne couvre pas le comportement, ou le couvre de
façon trop générique pour le contexte de l'organisation, et elle reste ancrée
au langage commun par son champ `technique_mitre_liee`. Le serveur le sert en
**lecture seule** : aucun outil n'écrit jamais dans le fichier.

Au lancement, le serveur charge ou télécharge les deux matrices depuis
`attack-stix-data`, le dépôt STIX canonique de MITRE, dans le dossier local
`MITRE_DB/`, avec écriture atomique du cache, puis lit le référentiel interne.
La release ATT&CK chargée est rappelée dans **chaque réponse** via le champ
`db_version` : tout mapping produit est daté d'une version précise du
catalogue.

Chaque appel d'outil et chaque événement système est consigné dans un fichier
JSONL sous `Logs/`. Les dossiers `MITRE_DB/` et `Logs/` sont créés
automatiquement au premier lancement.

Transport : **stdio par défaut**, en sous-processus local de l'agent, comme en
v2.1. Un mode `--http` s'y ajoute pour les clients qui ne parlent pas stdio (le
nœud MCP de n8n attend SSE ou HTTP Streamable) ; il écoute sur la boucle locale
et n'embarque aucune couche d'authentification. L'exposition réseau et la
sécurisation relèvent du jalon production.

## Pré-requis

* **Python 3.8+** — bibliothèque standard uniquement, aucun `pip` requis.
* **Claude Desktop** ou tout client compatible MCP.

## Installation

1. Cloner le dépôt et lancer une première fois :

```bash
git clone https://github.com/hq-bac-a-sable/mcp-attack-framework.git
cd mcp-attack-framework
python mcp_mitre.py --test
```

2. Créer le référentiel interne à partir du gabarit fourni (facultatif : en son
   absence, le serveur démarre normalement avec zéro fiche) :

```bash
cp referentiel_interne.exemple.json referentiel_interne.json
```

3. Déclarer le serveur dans `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "mitre": {
      "command": "python",
      "args": ["C:/chemin/vers/votre/dossier/mcp_mitre.py"]
    }
  }
}
```

4. Redémarrer Claude Desktop.

## Vérification

```bash
python mcp_mitre.py --test
```

`--test` **vérifie** au lieu d'afficher : il sort en **code 1** si une matrice
est vide, si les liens tactique-technique sont absents, si la couverture de
détection est anormale, si l'index des sources est vide, si une réciprocité est
rompue, s'il subsiste une **référence orpheline** (une relation qui pointe vers
un objet absent de la base, campagnes et équipements compris), si un alias
masque un outil, ou si l'index du référentiel interne est incohérent. Il est
utilisable tel quel en intégration continue.

Sortie attendue (catalogue ATT&CK 19.2 ; les chiffres évoluent avec les
releases MITRE) :

```
Serveur : mcp-mitre-attack v2.2.0
Source  : attack-stix-data
Releases: {'Enterprise': '19.2', 'ICS': '19.2'}
  Enterprise   15 tactiques,  697 techniques,  697 avec strategie,  652 avec source (modele: strategies)
  ICS          12 tactiques,   97 techniques,   97 avec strategie,   85 avec source (modele: strategies)
  Total       27 tactiques, 794 techniques, 178 groupes, 831 software, 96 mitigations
  Index       692 libelles de sources
  Liens       988 tactique-technique, 493 parent-sous-technique
  Revocations 158 redirections, 0 sans remplacant vivant, 24 depreciees
  Objets 2.2  58 campagnes, 18 assets ICS, index de recherche 4672 tokens / 1775 alias d'entites
  Integrite   0 anomalie(s) de reciprocite, 0 reference(s) orpheline(s)
Interne     2 fiche(s) (1 valide(s), 1 brouillon(s)), next_id THQ0003
            0 ecartee(s), 0 avertissement(s), 0 sans ancrage ATT&CK, 0 lien(s) revoque(s)
            source : /chemin/vers/referentiel_interne.json
Outils (18) : [...]
Alias  (16) : [...]
Transports : stdio (defaut) | http via --http [127.0.0.1:8733, sans authentification]
Audit : run_id=3a8e26bcc4fd
OK
```

Les fiches internes écartées (identifiant invalide, doublon, nom manquant) sont
affichées mais **ne font pas échouer** `--test` par défaut, car un dépôt peut
légitimement porter un référentiel en cours de nettoyage. Pour qu'elles
deviennent bloquantes en CI :

```bash
python mcp_mitre.py --test --strict
```

Autres options :

```bash
python mcp_mitre.py --http                  # transport HTTP local (défaut 127.0.0.1:8733)
python mcp_mitre.py --http --port 9000      # autre port
python mcp_mitre.py --no-audit              # démarre sans journal d'audit
python mcp_mitre.py --doc                   # documentation du module
python mcp_mitre.py --help                  # aide
```

Variables d'environnement : `MITRE_CACHE` (répertoire du cache, défaut
`MITRE_DB/`), `MITRE_LOGS` (répertoire du journal, défaut `Logs/`),
`MCP_INTERNAL_DB` (référentiel interne, défaut `referentiel_interne.json` à
côté du script), `MCP_HTTP_HOST` et `MCP_HTTP_PORT` (mode `--http`).

## Le référentiel interne

Fichier `referentiel_interne.json`, **versionné par l'équipe** et servi en
**lecture seule** : le serveur n'expose aucun outil d'écriture, ce qui rend
structurellement impossible la pollution du référentiel par un modèle de
langage.

Gabarit d'une fiche :

```json
{
  "id": "THQ0001",
  "name": "Phishing imitant le portail RH interne",
  "description": "Leurre imitant le portail RH pour voler des identifiants...",
  "technique_mitre_liee": "T1566.002",
  "tactique": "initial-access",
  "source_cti": "incident-2026-03",
  "statut": "valide",
  "auteur": "equipe-detection",
  "date_creation": "2026-03-18"
}
```

* `id` — format `THQ0000`, numérotation **continue, jamais réutilisée** : la
  marque haute ne redescend jamais, y compris après la suppression d'une fiche.
  En mémoire elle est monotone quoi qu'il arrive ; c'est au **redémarrage**
  qu'elle se perd, et redémarrer le client MCP est un geste quotidien. La clé
  `meta.dernier_id_attribue` la fait survivre à ce redémarrage et doit donc
  être **remontée à chaque nouvelle fiche** : sans elle, retirer la fiche la
  plus haute rend son numéro disponible et il sera réattribué à un autre
  comportement. Le serveur ne peut pas l'écrire (lecture seule), mais il
  **signale son absence** dans `anomalies`, dans le log et dans `--test`.
* `name` — **obligatoire** : une fiche sans nom est écartée.
* `description` — le comportement, et en quoi il est plus spécifique que MITRE.
* `technique_mitre_liee` — **obligatoire dès qu'une technique MITRE proche
  existe** : c'est l'ancrage ATT&CK de la fiche. Une fiche sans ancrage est
  chargée mais signalée.
* `statut` — `brouillon` ou `valide`. Toute autre valeur est **rétrogradée** à
  `brouillon`, jamais promue.
* Les champs libres (`tactique`, `source_cti`, `auteur`, dates, etc.) sont
  conservés tels quels et restitués par `get_internal_technique`.

**Contrôles au chargement.** Identifiant hors format et doublons rejetés ; nom
manquant rejeté ; statut inconnu rétrogradé ; technique MITRE liée inconnue de
la base signalée ; technique MITRE liée **révoquée** suivie jusqu'à son
remplaçant vivant, la fiche restant consultable depuis l'ancien comme depuis le
nouvel identifiant ; champs produits par le serveur (`db_version`,
`lecture_seule`, `error`, `note`, `anomalies`, `next_id`,
`internal_extensions`, `lien_revoque`…) retirés d'une fiche qui les porterait,
avec un avertissement les nommant, pour qu'un champ libre ne puisse jamais
usurper un champ de réponse. Un fichier illisible **ou introuvable** ne vide
pas un référentiel déjà chargé : l'état précédent est conservé et l'erreur est
journalisée. Les deux cas sont traités de la même façon, parce qu'une édition
humaine non atomique, un `git checkout` ou un `git stash` passe par un instant
sans fichier. Seul le **tout premier** chargement accepte un fichier absent, et
démarre alors normalement avec zéro fiche.

**Cycle de vie d'une fiche** : le LLM détecte un comportement non couvert →
`search_techniques` (MITRE d'abord) → `search_internal` (anti-doublon) →
proposition d'un **brouillon** au gabarit ci-dessus, numéroté avec le `next_id`
fourni par `list_internal_techniques` → un humain relit, complète, passe le
statut à `valide` et committe le fichier → `internal_reload` pour que le
serveur en tienne compte sans redémarrage.

## Les 18 outils MCP

| Outil | Ce qu'il fait |
|---|---|
| `search_techniques(query, limit?, matrix?, platform?, tactic?)` | Propose des techniques candidates : score normalisé [0..1], preuves (mots trouvés par champ), filtres de contexte. Les noms de groupes, software, campagnes et tactiques présents dans la requête servent d'indices |
| `get_technique(id)` | Confirme un candidat : description, matrice, tactiques, plateformes, **détections**, sous-techniques, groupes, software, **campagnes**, mitigations et **mitigations de la parente**, **équipements ICS visés**, **fiches internes rattachées** (`internal_extensions`). Redirige les identifiants révoqués (chaîne tracée par `via`) et signale les dépréciés |
| `get_tactics(matrix?)` | Les tactiques dans l'ordre officiel de la kill chain, par matrice |
| `get_tactic(id, matrix?)` | Une tactique et ses techniques parentes ; signale l'homonyme de l'autre matrice |
| `get_mitigations(technique_id)` | Les contre-mesures d'une technique, et celles de sa technique parente |
| `get_mitigation(id)` | Une contre-mesure et les techniques qu'elle couvre |
| `get_groups(technique_id?, matrix?)` | Groupes APT : top 50, ou ceux utilisant une technique — en direct et **via leurs campagnes** |
| `get_group(id)` | Détail d'un groupe APT : matrices, techniques, software, **campagnes** et **techniques observées uniquement en campagne** |
| `get_software(technique_id?)` | Software/malware : top 50, ceux associés à une technique, ou une fiche |
| `get_campaign(id)` | **Nouveau.** Détail d'une campagne (`Cxxxx`), par identifiant, nom ou alias : période, groupes attribués, techniques et software observés |
| `get_asset(id?)` | **Nouveau.** Équipements ICS (`Axxxx` : PLC, HMI, RTU…) et les techniques qui les visent. Sans argument : l'inventaire complet |
| `get_datasources(query, matrix?, limit?)` | Techniques observables depuis une source de données ou de logs. Le filtre `matrix` s'applique aux **libellés** autant qu'aux techniques ; `limit` règle la taille de la liste (60 par défaut, 300 au maximum) |
| `list_internal_techniques(statut?)` | Référentiel interne : liste, compteurs et **prochain identifiant libre**. `fiche_count` = taille du référentiel, `result_count` = fiches renvoyées après filtrage |
| `get_internal_technique(id)` | Détail d'une fiche, technique MITRE liée résolue (et son remplaçant si elle est révoquée) |
| `search_internal(query, limit?)` | Anti-doublon : recherche dans les fiches, **même fonction de score** que la recherche MITRE |
| `internal_reload()` | Relit le référentiel depuis le disque, sans redémarrer le serveur. Ne l'écrit jamais |
| `mitre_stats()` | Version du serveur, releases chargées, modèle de détection, fraîcheur du cache, statistiques, compteurs du référentiel |
| `mitre_update()` | Re-télécharge les deux matrices ; la base n'est remplacée qu'en cas de succès complet |

Les quatre outils internes et `mitre_stats` répondent **même si la base ATT&CK
est indisponible** : un échec de téléchargement ne rend pas le référentiel
maison inaccessible.

**Alias.** Les dix noms de la v1.1 — `mitre_search`, `mitre_technique`,
`mitre_tactics`, `mitre_tactic`, `mitre_mitigations`, `mitre_mitigation`,
`mitre_groups`, `mitre_group`, `mitre_software`, `mitre_datasources` — restent
acceptés en entrée, ainsi que quatre alias courts pour les outils internes
(`internal_list`, `internal_technique`, `internal_search`, `internal_refresh`)
et deux nouveaux (`mitre_campaign`, `mitre_asset`). Ils sont résolus à
l'exécution et n'apparaissent pas dans `tools/list`, donc ne consomment aucun
contexte côté modèle.

## La méthode de mapping encodée dans le serveur

1. **Une requête = un comportement atomique**, en mots-clés anglais ATT&CK
   (`lsass credential dumping`, pas trois comportements à la fois).

   La recherche est **lexicale, pas sémantique** : elle compare des **mots**,
   pas des **sens**. Elle ne sait pas que « vol de mots de passe » et
   « credential dumping » désignent la même chose, et le danger n'est pas
   qu'elle réponde vide, c'est qu'elle réponde *faux*. Mesuré : `vol de mots de
   passe` met en tête T1550.002 « Pass the Hash », uniquement parce que
   « passe » et « pass » convergent à la racinisation. La pondération par
   rareté de la v2.2 fait tomber ce score de 0,333 à **0,195**, sous le seuil
   faible, si bien que la réponse porte désormais l'avertissement — mais le
   candidat reste là, et il reste faux. En anglais courant le même piège existe
   avec un score plus élevé encore : `stealing passwords` → T1649 à **0,699**,
   qui n'est pas la bonne technique. C'est pour cela que les preuves (point 2)
   et la vérification (point 3) sont indispensables : un score seul ne prouve
   rien.
2. `search_techniques` renvoie des **candidats** avec un score normalisé
   **[0..1]** — ≥ 0,6 fort, < 0,3 faible, seuils rappelés dans la réponse — et
   des **preuves** : la liste exacte des mots trouvés, par champ. Le champ dit
   d'où vient la correspondance et ne vaut pas le même poids : `name` et
   `alias` (un acronyme défini dans la description, comme `RDP`) valent 1,
   `parent_name` 0,8, une entité citée dans la requête (`groups`, `software`,
   `campaigns`) 0,8, `tactic` 0,6, `description` 0,35. La correspondance se
   fait par **mots entiers racinisés** (algorithme de Porter) : « port » ne
   matche pas « support », « dumping » matche « dump », « services » matche
   « service ».
3. **Vérification obligatoire** : chaque candidat retenu est confirmé par
   `get_technique` (description complète, matrice, tactiques, détections), qui
   signale au passage les fiches internes rattachées.
4. **Parente d'abord** : à score égal, la technique parente précède ses
   sous-techniques ; on ne retient une sous-technique que si l'évidence la
   confirme (méthodologie CISA/MITRE). Le départage complet est : nom
   exactement égal à la requête, puis nom le mieux couvert, puis parente avant
   sous-technique, puis nom le plus court, puis identifiant.
5. **MITRE d'abord, interne ensuite** : `search_internal` confronte le
   comportement au référentiel maison, sans jamais remplacer la recherche
   MITRE. Quand aucun candidat MITRE n'est fort, `search_techniques` le
   rappelle explicitement dans sa note.
6. **Proposition, pas écriture** : si aucun mapping MITRE ni fiche interne ne
   couvre le comportement, le LLM propose un brouillon `THQ` (statut
   `brouillon`, identifiant `next_id`) — validation humaine obligatoire.
7. **Ne pas forcer** : liste vide ou scores faibles ⇒ « pas de mapping » est
   une conclusion valide, et le serveur l'indique explicitement. Pour que ce
   silence garde son sens, un **filtre invalide lève une erreur** au lieu de
   renvoyer zéro résultat : `matrix`, `platform` et `tactic` sont tous trois
   validés et nomment les valeurs acceptées.
8. **Identifiants révoqués ou dépréciés** : un ancien identifiant (`T1086`)
   renvoie une redirection explicite vers son remplaçant vivant (`T1059.001`)
   au lieu d'une erreur. Les révocations en chaîne sont résolues jusqu'à la
   cible finale, et le champ `via` donne les sauts intermédiaires. Une
   technique **dépréciée sans remplaçant** est signalée comme telle
   (`deprecated: true`), et non confondue avec un identifiant inexistant.
9. **Ne jamais mélanger les deux mondes** : le filtre `matrix` restreint la
   recherche à `Enterprise` ou `ICS` (aussi `IT`, `OT`, `SCADA`). Neuf noms de
   tactiques existent dans les deux matrices ; `get_tactic` signale toujours
   l'homonyme. Les équipements (`assets`) n'apparaissent que sur les techniques
   ICS.
10. **Traçabilité** : chaque réponse, y compris celles des outils internes,
    rappelle la release ATT&CK consultée (`db_version`).

## Détection : les deux modèles MITRE sont lus

Depuis sa release 18, MITRE décrit la détection par des **stratégies de
détection** reliées à des **analytics**, eux-mêmes reliés à des **sources de
logs** ; les anciens champs (`x_mitre_data_sources`, `x_mitre_detection`) ont
disparu des techniques. Jusqu'à la release 17.1, c'était l'inverse.

Ce serveur lit **les deux** et indique lequel il a trouvé via le champ
`detection_model` de `mitre_stats` (`strategies`, `hérité` ou `absent`) :

- `get_technique` renvoie une structure `detections` — stratégies de la
  technique, avec leurs analytics et leurs sources de logs (`WinEventLog:Sysmon`,
  `auditd:SYSCALL`) — et `legacy_detection` pour le texte des anciens
  catalogues ;
- `get_datasources` interroge un index de libellés reconstruit depuis les
  analytics (ex. `Process Creation` → 476 techniques sur la 19.2).

Les libellés composites `name:channel` ne sont construits que lorsque le canal
publié par MITRE en est réellement un : sans espace et d'au plus 40 caractères.
MITRE y publie parfois la logique de détection en texte libre, jusqu'à 225
caractères, qui polluerait l'index.

## Campagnes et équipements industriels

MITRE rattache une part importante des techniques d'un groupe à ses
**campagnes** plutôt qu'au groupe lui-même : APT29 déclare 66 techniques en
direct, et 53 de plus n'apparaissent que dans ses campagnes, dont 71 pour la
seule `C0024` « SolarWinds Compromise ». `get_group` distingue les deux listes
plutôt que de les fusionner — une technique observée en campagne attribuée
n'est pas la même affirmation qu'une technique attribuée au groupe — et cite la
campagne comme preuve. `get_campaign` accepte un identifiant, un nom ou un
alias, ce qui permet de partir du nom d'opération que donne un rapport CTI.

Côté ICS, les 18 objets `x-mitre-asset` (PLC, HMI, RTU, Data Historian, Safety
Controller…) sont exposés par `get_asset`, avec la relation `targets` dans les
deux sens : `get_asset("A0003")` donne les 61 techniques qui visent un
automate, et `get_technique("T0836")` donne les équipements que la technique
vise. C'est le chemin d'entrée qui manquait pour partir d'un **inventaire OT**
plutôt que d'un extrait de journal.

## Fichier d'audit

`Logs/mcp_audit.jsonl` trace l'exécution : démarrage avec la release chargée,
téléchargements et leur durée, chargement du cache, cache invalide, chargement,
rechargement et ré-ancrage du référentiel interne, les trois phases du cycle de
vie MCP (`initialize`, `tools_list`, `tool_call`), les erreurs de protocole,
l'arrêt. Chaque ligne porte le `run_id` de l'exécution et le `transport`
(`stdio` ou `http`), et chaque appel d'outil porte sa durée, ses arguments
tronqués et un résumé non sensible du résultat.
Écriture par thread dédié, non bloquante, file drainée intégralement à l'arrêt ;
si la file sature, une ligne `audit_dropped` publie le nombre de pertes.

```jsonl
{"ts":"2026-09-11T11:20:50.7","run_id":"33c63f0cc6fc","event":"internal_db_loaded","path":".../referentiel_interne.json","fiches":2,"rejets":0,"avertissements":0,"next_id":"THQ0003"}
{"ts":"2026-09-11T11:20:50.7","run_id":"33c63f0cc6fc","event":"server_start","pid":21508,"version":"2.2.0","transport":"stdio","db_version":{"Enterprise":"19.2","ICS":"19.2"},"ready":true,"tools":18}
{"ts":"2026-09-11T11:20:50.7","run_id":"33c63f0cc6fc","event":"initialize","transport":"stdio","req_id":0,"protocol_requested":"2025-06-18","protocol_negotiated":"2025-06-18","client":"claude-desktop"}
{"ts":"2026-09-11T11:20:50.7","run_id":"33c63f0cc6fc","event":"tool_call","transport":"stdio","req_id":13,"tool":"search_techniques","status":"success","duration_ms":3,"args":{"query":"lateral movement rdp","limit":"2"},"result":{"bytes":1195,"result_count":2,"total_matches":114,"top_score":0.758,"top_id":"T1021.001"}}
```

Affichage en direct sous PowerShell :

```powershell
Get-Content -Path ".\Logs\mcp_audit.jsonl" -Wait -Tail 20
```

## Transport HTTP local

Le mode `--http` sert exactement le même protocole et les mêmes outils que le
mode stdio : le moteur de mapping et le routeur de messages sont partagés, seul
le champ `transport` du journal les distingue. Il existe pour les clients qui
ne parlent pas stdio.

```bash
python mcp_mitre.py --http
```

- **Streamable HTTP** : `POST /mcp` → réponse JSON, ou trame SSE si le client
  ne déclare accepter que `text/event-stream` ; `GET /mcp` → flux de
  notifications maintenu ouvert.
- **HTTP+SSE (hérité)** : `GET /sse` annonce l'URL de dépôt, puis
  `POST /messages`.
- **Sonde de vivacité** : `GET /healthz`.

Le serveur reste **sans état** : aucun identifiant de session n'est exigé. La
mise à jour de la base (`mitre_update`) et la relecture du référentiel se font
sous verrou, ce mode servant plusieurs requêtes en parallèle.

## Limites connues

- Domaine Mobile non couvert.
- Recherche lexicale et non sémantique, côté MITRE comme côté référentiel
  interne.
- Le référentiel interne est en lecture seule par conception : toute création
  ou validation de fiche passe par l'édition humaine du JSON.
- Le cache n'expire pas seul : `mitre_stats` signale son âge et lève un drapeau
  `stale` au-delà de 30 jours.
- Transport stdio par défaut ; le mode `--http` écoute sur la boucle locale et
  n'embarque ni authentification ni chiffrement.
