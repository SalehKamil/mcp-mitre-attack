# Serveur MCP MITRE ATT&CK — Hybride Enterprise + ICS (v2.0)

Serveur MCP qui expose à un modèle de langage une base de connaissance MITRE
ATT&CK **hybride Enterprise (IT) et ICS (OT)**, conçue pour du **mapping TTP de
haute précision** selon la méthode *proposer puis vérifier* :
`search_techniques` propose des candidats scorés avec preuves, `get_technique`
confirme chaque candidat avant conclusion.

Au lancement, le serveur charge ou télécharge les deux matrices depuis
`attack-stix-data`, le dépôt STIX canonique de MITRE, dans le dossier local
`MITRE_DB/`, avec écriture atomique du cache. La release ATT&CK chargée est
rappelée dans **chaque réponse** via le champ `db_version` : tout mapping
produit est daté d'une version précise du catalogue.

Chaque appel d'outil et chaque événement système est consigné dans un fichier
JSONL sous `Logs/`. Les dossiers `MITRE_DB/` et `Logs/` sont créés
automatiquement au premier lancement.

Transport : **stdio uniquement**, en sous-processus local de l'agent. Cette
version n'écoute pas sur le réseau et n'embarque aucune couche
d'authentification — c'est le modèle normal d'un serveur MCP local.
L'exposition réseau et la sécurisation relèvent du jalon production.

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

2. Déclarer le serveur dans `claude_desktop_config.json` :

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

3. Redémarrer Claude Desktop.

## Vérification

```bash
python mcp_mitre.py --test
```

`--test` **vérifie** au lieu d'afficher : il sort en **code 1** si une matrice
est vide, si les liens tactique-technique sont absents, si la couverture de
détection est anormale, si l'index des sources est vide ou si une réciprocité
est rompue. Il est utilisable tel quel en intégration continue.

Sortie attendue (catalogue ATT&CK 19.2 ; les chiffres évoluent avec les
releases MITRE) :

```
Serveur : mcp-mitre-attack v2.0
Source  : attack-stix-data
Releases: {'Enterprise': '19.2', 'ICS': '19.2'}
  Enterprise   15 tactiques,  697 techniques,  697 avec strategie,  652 avec source (modele: strategies)
  ICS          12 tactiques,   97 techniques,   97 avec strategie,   85 avec source (modele: strategies)
  Total       27 tactiques, 794 techniques, 178 groupes, 831 software, 96 mitigations
  Index       692 libelles de sources
  Liens       988 tactique-technique, 493 parent-sous-technique
  Revocations 158 redirections, 0 sans remplacant vivant
  Integrite   0 anomalie(s) de reciprocite
OK
```

Autres options :

```bash
python mcp_mitre.py --no-audit    # démarre sans journal d'audit
python mcp_mitre.py --help        # aide
```

Variables d'environnement : `MITRE_CACHE` (répertoire du cache, défaut
`MITRE_DB/`) et `MITRE_LOGS` (répertoire du journal, défaut `Logs/`).

## Les 12 outils MCP

| Outil | Ce qu'il fait |
|---|---|
| `search_techniques(query, limit?, matrix?, platform?, tactic?)` | Propose des techniques candidates : score normalisé [0..1], preuves (mots trouvés par champ), filtres de contexte |
| `get_technique(id)` | Confirme un candidat : description, matrice, tactiques, plateformes, **détections**, sous-techniques, groupes, software, mitigations. Redirige les identifiants révoqués |
| `get_tactics(matrix?)` | Les tactiques dans l'ordre officiel de la kill chain, par matrice |
| `get_tactic(id, matrix?)` | Une tactique et ses techniques parentes ; signale l'homonyme de l'autre matrice |
| `get_mitigations(technique_id)` | Les contre-mesures d'une technique |
| `get_mitigation(id)` | Une contre-mesure et les techniques qu'elle couvre |
| `get_groups(technique_id?, matrix?)` | Groupes APT : top 50, ou ceux utilisant une technique |
| `get_group(id)` | Détail d'un groupe APT (matrices, techniques, software) |
| `get_software(technique_id?)` | Software/malware : top 50, ceux associés à une technique, ou une fiche |
| `get_datasources(query, matrix?)` | Techniques observables depuis une source de données ou de logs |
| `mitre_stats()` | Version du serveur, releases chargées, modèle de détection, fraîcheur du cache, statistiques |
| `mitre_update()` | Re-télécharge les deux matrices ; la base n'est remplacée qu'en cas de succès complet |

**Alias.** Les dix noms de la v1.1 — `mitre_search`, `mitre_technique`,
`mitre_tactics`, `mitre_tactic`, `mitre_mitigations`, `mitre_mitigation`,
`mitre_groups`, `mitre_group`, `mitre_software`, `mitre_datasources` — restent
acceptés en entrée. Ils sont résolus à l'exécution et n'apparaissent pas dans
`tools/list`, donc ne consomment aucun contexte côté modèle.

## La méthode de mapping encodée dans le serveur

1. **Une requête = un comportement atomique**, en mots-clés anglais ATT&CK
   (`lsass credential dumping`, pas trois comportements à la fois).

   La recherche est **lexicale, pas sémantique** : elle compare des **mots**,
   pas des **sens**. Elle ne sait pas que « vol de mots de passe » et
   « credential dumping » désignent la même chose. Une requête en français
   renvoie 0 candidat ; une requête en anglais courant peut renvoyer une
   réponse *fausse* avec un score élevé (`stealing passwords` → T1649 à 0,675,
   qui n'est pas la bonne technique). C'est pour cela que les preuves (point 2)
   et la vérification (point 3) sont indispensables. Le détail est développé
   dans les notes de version.
2. `search_techniques` renvoie des **candidats** avec un score normalisé
   **[0..1]** — ≥ 0,6 fort, < 0,3 faible, seuils rappelés dans la réponse — et
   des **preuves** : la liste exacte des mots trouvés dans le nom et dans la
   description. La correspondance se fait par **mots entiers racinisés** :
   « port » ne matche pas « support », « dumping » matche « dump »,
   « services » matche « service ».
3. **Vérification obligatoire** : chaque candidat retenu est confirmé par
   `get_technique` (description complète, matrice, tactiques, détections).
4. **Parente d'abord** : à score égal, la technique parente précède ses
   sous-techniques ; on ne retient une sous-technique que si l'évidence la
   confirme (méthodologie CISA/MITRE).
5. **Ne pas forcer** : liste vide ou scores faibles ⇒ « pas de mapping » est
   une conclusion valide, et le serveur l'indique explicitement.
6. **Identifiants révoqués** : un ancien identifiant (`T1086`) renvoie une
   redirection explicite vers son remplaçant vivant (`T1059.001`) au lieu d'une
   erreur. Les révocations en chaîne sont résolues jusqu'à la cible finale.
7. **Ne jamais mélanger les deux mondes** : le filtre `matrix` restreint la
   recherche à `Enterprise` ou `ICS` (aussi `IT`, `OT`, `SCADA`). Neuf noms de
   tactiques existent dans les deux matrices ; `get_tactic` signale toujours
   l'homonyme.
8. **Traçabilité** : chaque réponse rappelle la release ATT&CK consultée
   (`db_version`).

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

## Fichier d'audit

`Logs/mcp_audit.jsonl` trace l'exécution : démarrage avec la release chargée,
téléchargements et leur durée, chargement du cache, cache invalide, appels
d'outils avec leur statut, arrêt. Écriture par thread dédié, non bloquante,
file drainée intégralement à l'arrêt.

```jsonl
{"ts":"2026-09-11T05:16:55.357","event":"db_loaded","matrix":"Enterprise","source":"cache","release":"19.2","techniques":697}
{"ts":"2026-09-11T05:16:55.358","event":"server_start","pid":21508,"version":"2.0","db_version":{"Enterprise":"19.2","ICS":"19.2"},"ready":true,"tools":12}
{"ts":"2026-09-11T05:16:55.360","event":"tool_call","tool":"search_techniques","status":"success"}
```

Affichage en direct sous PowerShell :

```powershell
Get-Content -Path ".\Logs\mcp_audit.jsonl" -Wait -Tail 20
```

## Limites connues

- Domaine Mobile non couvert ; campagnes et ressources industrielles
  (`x-mitre-asset`) non exposées.
- Recherche lexicale et non sémantique ; racinisation volontairement légère
  (`execute` et `execution` ne convergent pas).
- Le cache n'expire pas seul : `mitre_stats` signale son âge et lève un drapeau
  `stale` au-delà de 30 jours.
- Transport stdio uniquement, sans authentification ni exposition réseau.
