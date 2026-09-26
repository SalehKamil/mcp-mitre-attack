# MCP MITRE ATT&CK — Enterprise + ICS

Ce serveur MCP expose les bases de connaissances MITRE ATT&CK **Enterprise (IT)** et **ICS (OT)** à un modèle de langage (LLM) compatible, ici Claude Desktop. Les deux matrices sont fusionnées dans une base unique, mais restent cloisonnées : chaque objet porte sa matrice d'origine, et le serveur ne rattache jamais une technique industrielle à une tactique bureautique. Un même échange peut donc traiter une intrusion sur un poste Windows et une manipulation de procédé sur un automate, sans confusion entre les deux mondes.

Au premier lancement, les deux bases sont téléchargées depuis le dépôt officiel GitHub de MITRE (environ 48 MB pour Enterprise et 3 MB pour ICS au format STIX), analysées, fusionnées, puis mises en cache localement sous forme condensée (environ 5 MB). Les lancements suivants sont instantanés. Le téléchargement se fait en arrière-plan : le serveur répond à son client dès le démarrage, même si la base n'est pas encore prête.

---

## Prérequis

Python 3.8 ou supérieur et un client MCP compatible (Claude Desktop). Aucune dépendance externe n'est requise.

---

## Installation et lancement

```bash
git clone https://github.com/hq-bac-a-sable/mcp-attack-framework.git
cd mcp-attack-framework
python mcp_mitre.py
```

Le script n'ayant aucune dépendance, il fonctionne aussi bien avec `uv` :

```bash
uv run mcp_mitre.py
```

Pour vérifier que les deux matrices sont correctement chargées :

```bash
python mcp_mitre.py --test
```

La sortie attendue détaille chaque matrice séparément, puis les totaux et le nombre de liens reconstruits :

```
Serveur : mcp-mitre v1.1.0
MITRE   : github.com/mitre/cti (spec 3.3.0)
  Enterprise   15 tactiques,  697 techniques,  697 avec detection
  ICS          12 tactiques,   97 techniques,   97 avec detection
  Total       27 tactiques, 794 techniques
              178 groupes, 831 software, 96 mitigations
              2796 sources de donnees
  Liens       988 tactique-technique, 493 parent-sous-technique
Outils (12) : ['mitre_stats', 'mitre_update', ...]
Alias   (9) : ['get_tactics', 'get_tactic', ...]
OK
```

Le diagnostic ne se contente pas d'afficher des compteurs, il les vérifie. Si une matrice est vide, ou si le nombre de liens tactique-technique tombe à zéro, la commande affiche `ECHEC` et sort en code 1. Ce contrôle est utilisable tel quel dans une chaîne d'intégration : une régression de parsing qui viderait silencieusement un rattachement est détectée au lieu de se propager jusqu'aux réponses du modèle.

`python mcp_mitre.py --help` affiche les options disponibles. `--no-audit` démarre le serveur sans journal d'audit.

---

## Configuration Claude Desktop

Modifier votre fichier `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "mitre": {
      "command": "python",
      "args": ["C:\\chemin\\vers\\mcp_mitre.py"]
    }
  }
}
```

Emplacement du fichier :
- Windows : `%APPDATA%\Claude\claude_desktop_config.json`
- macOS : `~/Library/Application Support/Claude/claude_desktop_config.json`

Redémarrer Claude Desktop après modification. Les journaux du serveur sont écrits sur la sortie d'erreur standard et visibles dans les logs MCP du client.

---

## Outils MCP disponibles

| Outil | Description |
|---|---|
| `mitre_stats` | Statistiques de la base, par matrice, et fraîcheur du cache |
| `mitre_update` | Re-télécharge les deux matrices depuis GitHub |
| `mitre_tactics` | Les tactiques ATT&CK dans l'ordre de la kill chain, par matrice |
| `mitre_tactic` | Détails d'une tactique et ses techniques |
| `mitre_search` | Recherche scorée de techniques candidates, avec preuves de correspondance |
| `mitre_technique` | Détails complets d'une technique Enterprise ou ICS |
| `mitre_groups` | Groupes APT, filtrables par technique ou par matrice |
| `mitre_group` | Détails d'un groupe APT |
| `mitre_software` | Logiciels et malwares, filtrables par technique |
| `mitre_mitigations` | Mitigations pour une technique donnée |
| `mitre_mitigation` | Détails d'une contre-mesure et des techniques qu'elle couvre |
| `mitre_datasources` | Techniques détectables par une source de données |

### Détail des fonctions

**`mitre_stats`** — Sans argument. Retourne la source, la version de spécification ATT&CK, l'âge du cache en jours et le décompte de chaque type d'objet, avec un sous-total par matrice. Le champ `stale` passe à `true` au-delà de 30 jours.

**`mitre_update`** — Sans argument. Force un nouveau téléchargement des deux matrices et reconstruit le cache. La base en mémoire n'est remplacée qu'une fois les deux bundles récupérés et analysés avec succès : un échec réseau en cours de route laisse la base existante intacte et le signale dans la réponse. Le fichier de cache lui-même n'est écrit qu'après une reconstruction complète, via un remplacement atomique.

**`mitre_tactics`** — Accepte un argument `matrix` optionnel (`Enterprise`, `ICS`, ou vide pour les deux). Retourne les tactiques dans l'ordre canonique de la kill chain, lu directement dans la matrice publiée par MITRE, avec le nombre de techniques rattachées à chacune. Les deux matrices ayant leur propre ordre officiel, chacune est restituée dans le sien.

**`mitre_tactic(id, matrix)`** — Accepte un identifiant (`TA0002`, `TA0110`) ou un nom (`Execution`, `Impair Process Control`). Retourne la description de la tactique et la liste de ses techniques parentes avec leur nombre de sous-techniques. Plusieurs noms de tactiques existent dans les deux matrices sous des identifiants différents : `Persistence` est à la fois `TA0003` côté Enterprise et `TA0110` côté ICS. L'argument `matrix` lève l'ambiguïté, et la réponse signale systématiquement l'existence d'un homonyme dans l'autre matrice via le champ `homonyme_autre_matrice`.

**`mitre_search(query, matrix, limit)`** — Recherche pondérée sur l'identifiant, le nom, la description, les sources de données, les canaux de journalisation et le texte des analytics de détection, dans les deux matrices. Un identifiant d'événement comme `4688`, un nom de canal comme `WinEventLog:Security` ou `AWS:CloudTrail`, un nom de binaire comme `rundll32`, un terme industriel comme `modify controller tasking` sont donc des requêtes valides. Les correspondances exactes sur l'identifiant puis sur le nom sont priorisées, et la numérotation des sous-techniques est normalisée avant comparaison.

Chaque candidat est accompagné de sa matrice, de son score et d'un champ `matched_in` qui indique où la correspondance a eu lieu : `id`, `name`, `description`, `data_source` ou `detection`. C'est l'information qui permet au modèle de distinguer une correspondance sérieuse d'une coïncidence de sous-chaîne, la recherche étant lexicale. Un candidat qui ne matche que sur `description` mérite d'être écarté avant même d'être confirmé. Le tri est déterministe, par score décroissant puis par identifiant. L'argument `matrix` restreint la recherche à un seul monde, `limit` borne le nombre de candidats (25 par défaut, 50 au maximum).

**`mitre_technique(id)`** — Accepte `T1059.001`, `t1059.001`, `T1059.1` ou `T0831`, la numérotation des sous-techniques étant normalisée et les identifiants ICS traités comme les autres. Retourne la matrice, la description, les tactiques de rattachement, les plateformes, la technique parente et les sous-techniques, les sources de données et canaux de logs associés, les stratégies de détection avec leurs analytics et leurs paramètres de réglage, ainsi que les groupes APT, logiciels et mitigations liés.

**`mitre_groups(technique_id, matrix)`** — Sans argument, retourne les 50 groupes les plus actifs par nombre de techniques. Avec un identifiant de technique, retourne les groupes connus pour l'utiliser. L'argument `matrix` restreint aux groupes actifs sur une matrice donnée, ce qui isole par exemple les acteurs documentés sur des systèmes industriels.

**`mitre_group(id)`** — Accepte un identifiant (`G0034`), un nom (`Sandworm Team`) ou n'importe quel alias publié (`ELECTRUM`, `Telebots`, `IRON VIKING`). Retourne la fiche du groupe, ses alias, ses techniques avec leur tactique, et ses logiciels. Douze groupes sont documentés dans les deux matrices à la fois : leur champ `matrices` contient alors `["Enterprise", "ICS"]`, et chaque technique retournée est annotée de sa propre matrice, de sorte que le modèle voit d'un coup d'œil la partie IT et la partie OT de l'arsenal.

**`mitre_software(technique_id)`** — Sans argument, retourne les 50 logiciels les plus répandus. Avec un identifiant de technique, retourne les logiciels qui l'utilisent. Avec un identifiant `S****` ou un nom (`Mimikatz`, `Industroyer`), retourne la fiche détaillée du logiciel. Dix-sept logiciels sont présents dans les deux matrices et suivent la même convention que les groupes.

**`mitre_mitigations(technique_id)`** — Retourne les mitigations officielles associées à une technique, avec leur description complète et leur URL.

**`mitre_mitigation(id)`** — Accepte un identifiant Enterprise (`M1043`), un identifiant ICS (`M0801`) ou un nom. Retourne la fiche de la contre-mesure et la liste complète des techniques qu'elle couvre. C'est le chemin à emprunter pour élargir une recommandation : partir de la mitigation citée par une technique et voir ce qu'elle protège par ailleurs.

**`mitre_datasources(query, matrix)`** — Recherche par sous-chaîne sur les composants de données, les sources de journalisation et les canaux, dans les deux matrices. `Process Creation`, `WinEventLog:Security`, `4688`, `linux:syslog`, `AWS:CloudTrail` ou `Operational Databases` sont des requêtes valides. Retourne les sources correspondantes et les techniques observables à partir de celles-ci.

### Nomenclature et alias

Les douze outils suivent une nomenclature `mitre_*` stable. Le préfixe n'est pas décoratif : lorsque plusieurs serveurs MCP sont branchés sur le même client, il évite la collision avec des outils génériques d'un autre serveur.

Neuf alias `get_*` sont acceptés en entrée par compatibilité (`get_technique`, `get_tactic`, `search_techniques`, `get_mitigation`, etc.). Ils ne sont pas exposés dans `tools/list`, donc ne consomment aucun contexte côté modèle, mais un appel utilisant ces noms est résolu vers l'outil correspondant.

### Conventions de réponse

Toutes les réponses sont du JSON. Les listes potentiellement longues sont tronquées et accompagnées d'un bloc indiquant le nombre d'éléments affichés, le total et si une troncature a eu lieu, afin que le modèle sache qu'il ne voit qu'une partie du résultat. Une entité introuvable retourne un objet `error` plutôt qu'une exception, et un argument invalide retourne un `error` accompagné de la liste des paramètres attendus.

Chaque tactique, technique et mitigation porte un champ `matrix` valant `Enterprise` ou `ICS`. Les groupes et les logiciels portent un champ `matrices` qui est une liste, parce qu'un même acteur peut être documenté dans les deux. Cette distinction est volontaire : elle permet au modèle de vérifier qu'il ne mélange pas les deux mondes sans avoir à interpréter une valeur composite.

---

## Journal d'audit

Chaque appel d'outil et chaque événement de cycle de vie du serveur est consigné dans `Logs/mcp_audit.jsonl` : démarrage, téléchargements avec leur durée, chargement du cache, appels d'outils avec leur statut, arrêt. L'écriture est assurée par un thread dédié qui vide la file par lots, donc elle ne bloque jamais la réponse à un outil, et la file est drainée intégralement à l'arrêt pour qu'aucun événement ne soit perdu.

```jsonl
{"ts": "2026-03-20T10:44:22.442994", "event": "download_start", "matrix": "Enterprise", "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"}
{"ts": "2026-03-20T10:44:29.201086", "event": "download_complete", "matrix": "Enterprise", "duration_ms": 6757}
{"ts": "2026-03-20T10:44:30.029646", "event": "server_start", "pid": 21508, "version": "1.1.0", "tools": 12}
{"ts": "2026-03-20T10:45:03.114210", "event": "tool_call", "tool": "mitre_technique", "status": "success"}
{"ts": "2026-03-20T11:12:00.000000", "event": "server_stop"}
```

Affichage en direct sous PowerShell :

```powershell
Get-Content -Path ".\Logs\mcp_audit.jsonl" -Wait -Tail 20
```

Le répertoire est redéfinissable par la variable d'environnement `MITRE_LOGS`, et le journal se désactive avec `--no-audit`.

---

## Évaluation du prototype

Pour évaluer la qualité du mapping, il est recommandé de soumettre au modèle des logs réels ou simulés et d'observer sa capacité à identifier les techniques ATT&CK correspondantes. On peut utiliser des journaux d'événements Windows, des alertes SIEM, des signaux réseau suspects, mais aussi des traces de protocoles industriels ou des relevés de procédé, puis comparer les résultats obtenus avec les techniques attendues. Cette approche permet de mesurer concrètement la précision du tool calling, la pertinence du raisonnement et la capacité à reconstruire une kill chain complète à partir d'une séquence d'événements.

Côté IT, le chemin le plus direct consiste à partir d'un identifiant d'événement observé et à remonter vers les techniques : un `4688` avec une ligne de commande suspecte, un `4624` de type 3 inhabituel, un appel CloudTrail atypique. Les analytics retournées par `mitre_technique` décrivent les conditions de détection et les éléments à ajuster pour limiter les faux positifs.

Côté OT, le vocabulaire diffère et la recherche par mots-clés porte moins bien. Le chemin fiable passe par la tactique : identifier l'intention du signal observé (inhiber une fonction de sécurité, altérer une consigne, masquer l'état réel du procédé), appeler `mitre_tactic` sur la tactique ICS correspondante, puis parcourir ses techniques par leur nom.

Le fichier `prompts.md` fournit un prompt système prêt à l'emploi pour ce travail d'analyse, ainsi qu'une série de prompts de validation permettant de vérifier que le serveur répond correctement sur chacun de ses chemins d'accès.

---

## Données

La base provient du dépôt officiel [github.com/mitre/cti](https://github.com/mitre/cti), au format STIX 2.1, domaines Enterprise ATT&CK et ATT&CK for ICS.

Les objets révoqués et dépréciés sont écartés au chargement. Les deux bundles sont indexés ensemble, puis les liens sont reconstruits en deux passes successives : d'abord le rattachement des techniques à leurs tactiques, ensuite les relations `uses`, `mitigates`, `subtechnique-of` et `detects`. Le résultat ne dépend donc ni de l'ordre dans lequel MITRE publie ses objets, ni de l'ordre dans lequel les deux matrices sont chargées.

Le rattachement d'une technique à sa tactique se fait à l'intérieur de sa propre matrice. Les identifiants courts STIX sont partagés entre les deux domaines : `persistence`, `execution`, `initial-access` et `lateral-movement` existent des deux côtés. Sans ce cloisonnement, une technique industrielle serait rattachée à la tactique bureautique homonyme, ce qui produirait des mappings faux au niveau tactique.

Les groupes et les logiciels, eux, portent les mêmes identifiants `G****` et `S****` dans les deux bundles, et y sont publiés sous le même identifiant STIX. Douze groupes et dix-sept logiciels sont ainsi présents deux fois. Ces objets sont fusionnés plutôt que dupliqués ou remplacés : la seconde occurrence enrichit la liste `matrices` de l'entrée existante sans écraser les relations déjà collectées.

La partie détection s'appuie sur les objets `x-mitre-detection-strategy`, `x-mitre-analytic` et `x-mitre-data-component`, qui portent les sources de journalisation et les canaux exploitables. Ce modèle est renseigné dans les deux domaines, y compris ICS, où il remplace les champs hérités `x_mitre_data_sources` et `x_mitre_detection` désormais vides. Les 794 techniques disposent d'au moins une stratégie de détection, et 737 d'entre elles portent des sources de données ou des canaux exploitables.

Le cache est écrit dans `MITRE_DB/attack.json` à côté du script, sous forme condensée plutôt qu'en STIX brut : environ 5 MB pour les deux matrices, contre 49 MB pour les bundles d'origine, et un rechargement à froid en moins de 200 ms. Ce chemin peut être redéfini par la variable d'environnement `MITRE_CACHE`. La mise à jour se fait via l'outil `mitre_update` ou en supprimant le fichier de cache.

Un cache illisible, tronqué, ou ne contenant qu'une seule des deux matrices est détecté au chargement et déclenche un nouveau téléchargement. C'est une précaution délibérée : un serveur qui démarrerait sur une base amputée annoncerait deux matrices tout en n'en servant qu'une, et le modèle mapperait tous les signaux IT dans la matrice industrielle sans aucun moyen de s'en apercevoir.

---

## Limites connues

- Domaine Mobile non couvert : Enterprise et ICS uniquement.
- Les campagnes (`campaign`) ne sont pas exposées, ni les ressources industrielles (`x-mitre-asset`) introduites côté ICS.
- La recherche est lexicale, sans correction orthographique ni synonymes : `powershell` fonctionne, `power shell` en deux mots ne renvoie rien. Le champ `matched_in` sert précisément à juger de la solidité d'une correspondance.
- Le vocabulaire ATT&CK évolue : la tactique `TA0005`, longtemps nommée « Defense Evasion », s'appelle désormais « Stealth », et une tactique `TA0112` « Defense Impairment » a été introduite. Le serveur lit ces libellés dans la base et suit donc le changement, mais un prompt rédigé sur l'ancienne nomenclature peut orienter le modèle vers des termes qui n'existent plus.
- Le cache n'expire pas automatiquement ; `mitre_stats` signale simplement qu'il a plus de 30 jours.
- Transport stdio uniquement, sans couche réseau ni authentification. C'est le modèle normal d'un serveur MCP local lancé en sous-processus par son client. L'exposition réseau et sa sécurisation relèvent du jalon production.
