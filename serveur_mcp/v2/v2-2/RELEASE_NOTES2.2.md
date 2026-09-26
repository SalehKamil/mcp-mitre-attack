# Release Notes — Serveur MCP MITRE ATT&CK v2.2 « campagnes, équipements ICS et recherche refondue »

## Vue d'ensemble

La v2.2.0 reprend le serveur v2.1 et lui ajoute **ce qu'ATT&CK publie et que le
serveur ne lisait pas** — les campagnes, les équipements industriels, les
techniques dépréciées — puis **refond la recherche** pour qu'elle propose la
bonne technique au bon niveau de la hiérarchie.

L'**interface de la v2.1 n'est pas touchée** : aucun de ses seize outils n'est
retiré, aucune signature n'est modifiée, aucun de ses garde-fous n'est levé.
Deux outils s'ajoutent — `get_campaign` et `get_asset` — et les quatorze alias
historiques restent acceptés, augmentés de deux. Les réponses des outils
existants gagnent des champs **additifs** (`via`, `deprecated`,
`parent_mitigations`, `campaigns`, `assets`, `full_name`, `acronyms`,
`techniques_via_campaigns`) ; aucune n'en perd. Le référentiel interne `THQ`
est servi exactement comme en v2.1, en lecture seule. Version mineure, sans
rupture.

Le code de la v2.1 est conservé ligne pour ligne partout où la greffe ne
l'exigeait pas : **2 043 de ses 2 236 lignes sont reprises telles quelles**, et
chaque bloc ajouté porte la mention `NOUVEAU v2.2` dans le source, pour qu'une
refonte future ne confonde pas un apport avec un garde-fou hérité.

Tous les exemples ci-dessous sont **mesurés** sur le serveur livré, chargé avec
ATT&CK 19.2 (Enterprise + ICS, 794 techniques) et le référentiel d'exemple
fourni.

---

## 1. Les campagnes : la moitié du profil d'un groupe qui manquait

MITRE publie 58 objets `campaign` en 19.2. La v2.1 ne les lisait pas, et ce
n'était pas un oubli anodin : MITRE rattache une part importante des techniques
d'un groupe à ses **campagnes** plutôt qu'au groupe lui-même. APT29 déclare 66
techniques en direct — et 53 de plus n'existent que dans ses campagnes.

Concrètement, en v2.1, un analyste qui demandait « APT29 utilise-t-il cette
technique ? » recevait un **non** pour un tiers du corpus réel. La réponse est
maintenant complète, et la campagne sert de preuve :

```
get_group("G0016")
→ "techniques":               {"count": 66, ...},
  "techniques_via_campaigns": {"count": 53, "items": [
      {"id": "T1003.006", "name": "DCSync", "campaigns": ["C0024"]},
      {"id": "T1001.002", "name": "Steganography", "campaigns": ["C0023"]}, ...]},
  "campaigns": [{"id": "C0023", ...}, {"id": "C0024", ...}]
```

Les deux listes restent **séparées** : une technique observée dans une campagne
attribuée n'est pas la même affirmation qu'une technique attribuée au groupe, et
le serveur ne les confond pas à la place de l'analyste. `get_groups(technique_id)`
suit la même règle avec un bloc `groups_via_campaigns`.

### `get_campaign(id)` — nouvel outil

Un rapport CTI nomme une opération plutôt qu'un groupe. L'outil accepte
l'identifiant, le nom ou un alias, et la résolution partielle de la v2.1
s'applique comme pour les groupes :

```
get_campaign("C0024")
→ {"id": "C0024", "name": "SolarWinds Compromise",
   "first_seen": "2019-08-01", "last_seen": "2021-01-01",
   "groups": [{"id": "G0016", "name": "APT29"}],
   "techniques": {"count": 71, ...}, "software": {"count": 11, ...}}

get_campaign("Dream Job")
→ {"id": "C0022", "name": "Operation Dream Job", "techniques": {"count": 55, ...},
   "resolution": {"mode": "partiel", "candidats": [{"id": "C0022", ...}]}}
```

`get_technique` signale désormais les campagnes où la technique a été observée :
`T1566.002` en porte 9.

## 2. Les équipements ICS : partir de l'inventaire OT

MITRE publie 18 objets `x-mitre-asset` (PLC, HMI, RTU, Data Historian, Safety
Controller…) et la relation `targets` qui les relie aux techniques. La v2.1 les
ignorait, ce qui fermait le seul chemin d'entrée naturel en environnement
industriel : **partir de ce qu'on exploite**, et non d'un extrait de journal.

```
get_asset()                       # sans argument : l'inventaire
→ {"assets": [{"id": "A0001", "name": "Workstation", "technique_count": 51},
              {"id": "A0002", "name": "Human-Machine Interface (HMI)", ...: 57},
              {"id": "A0003", "name": "Programmable Logic Controller (PLC)", ...: 61},
              {"id": "A0004", "name": "Remote Terminal Unit (RTU)", ...: 45}, ...]}

get_asset("A0003")
→ {"name": "Programmable Logic Controller (PLC)", "matrix": "ICS",
   "techniques": {"count": 61, ...}}
```

Le chemin inverse est exposé sur la technique, et seulement pour la matrice où
il a un sens :

```
get_technique("T0836")            # Modify Parameter
→ ..., "assets": [{"id": "A0003", "name": "Programmable Logic Controller (PLC)"},
                  {"id": "A0004", "name": "Remote Terminal Unit (RTU)"},
                  {"id": "A0005", "name": "Intelligent Electronic Device (IED)"}, ...]
```

Le champ `assets` n'apparaît que sur les techniques ICS : une technique
Enterprise ne se voit pas attribuer un équipement industriel par inadvertance.

## 3. Techniques dépréciées, et chaînes de révocation tracées

**24 techniques sont dépréciées sans remplaçant** dans la 19.2. La v2.1 les
traitait comme des identifiants inexistants — la même réponse que pour une
faute de frappe, alors que les deux situations appellent des gestes opposés :
corriger la saisie d'un côté, remapper le comportement de l'autre.

```
get_technique("T1064")
→ {"deprecated": true, "requested": "T1064", "name": "Scripting",
   "note": "'T1064' (Scripting) est DEPRECIEE par MITRE sans remplacant :
            ne plus l'utiliser dans un mapping ; chercher le comportement
            avec search_techniques"}
```

`search_techniques` le signale aussi lorsqu'un identifiant déprécié apparaît
dans la requête, au lieu de chercher silencieusement autre chose.

**Les chaînes de révocation sont tracées.** La résolution transitive existait
déjà en v2.1 : `T1073` menait bien jusqu'à `T1574.001`. Ce qui manquait, c'est
le **chemin** — indispensable quand une fiche interne ou un ancien rapport cite
l'identifiant intermédiaire :

```
get_technique("T1073")
→ {"redirect": true, "requested": "T1073", "replaced_by": "T1574.001",
   "via": ["T1574.002"], "remplacant_vivant": true,
   "note": "'T1073' est revoquee : consulter T1574.001 via get_technique
            (chaine de revocation : T1574.002)"}
```

## 4. Les mitigations de la technique parente

Dans ATT&CK, les contre-mesures sont le plus souvent rattachées à la technique
**parente**, pas à chacune de ses sous-techniques. Une sous-technique
interrogée seule renvoyait donc une liste courte, alors que des mesures
parfaitement valides existaient un niveau au-dessus — et rien ne le disait.

```
get_technique("T1566.002")
→ ..., "mitigations":        {"count": 5, ...},
       "parent_mitigations": {"count": 6, ...}    # celles de T1566
```

Les deux listes restent distinctes, pour la même raison qu'au §1 : ce sont deux
affirmations différentes. `get_mitigations` expose les mêmes champs, avec
l'identifiant et le nom de la parente.

## 5. La recherche refondue

`search_techniques` reste **lexicale et non sémantique** — elle compare des
mots, pas des sens — et rend toujours un score normalisé `[0..1]` avec ses
preuves dans `matched`. C'est la façon de peser les mots qui change. Trois
requêtes, mêmes données, avant et après :

```
search_techniques("lsass credential dumping")
  v2.1 → T1003     0.667   matched: {"name": ["credential", "dump"]}
         T1003.001 0.567
  v2.2 → T1003.001 0.894   matched: {"name": ["lsass"],
                                     "parent_name": ["credenti", "dump"]}
         T1003     0.531

search_techniques("rdp")
  v2.1 → T1563.002 1.0     (T1021.001 « Remote Desktop Protocol » noyé)
  v2.2 → T1021.001 1.0     matched: {"alias": ["rdp"]}
         T1563.002 1.0     matched: {"name": ["rdp"], "phrase": true}

search_techniques("apt29 cobalt strike")
  v2.1 → T1588.002 0.233   matched: {"description": ["cobalt", "strik"]}
  v2.2 → T1105     0.9     matched: {"groups": ["G0016 APT29"],
                                     "software": ["S0154 Cobalt Strike"]}
```

Cinq mécanismes produisent ces chiffres.

**Le nom de la technique parente est indexé sur la sous-technique**, comme le
site ATT&CK l'affiche : « OS Credential Dumping: LSASS Memory ». Une requête
qui mêle le comportement générique et le détail spécifique trouve désormais le
niveau le plus précis, au lieu de récompenser la parente qui porte les mots
communs. Le champ `full_name` restitue ce nom complet dans les résultats.

**Les acronymes définis dans les descriptions sont indexés au poids du nom.**
« Remote Desktop Protocol (RDP) » rend `T1021.001` trouvable par `rdp`. Chaque
acronyme est validé par ses initiales avant d'être retenu, pour ne pas indexer
n'importe quelle parenthèse ; ils sont visibles dans le champ `acronyms` de
`get_technique`.

**La racinisation passe à l'algorithme de Porter.** La racinisation légère de
la v2.1 était symétrique mais grossière : elle écrasait `lsass` sur `lsa` et ne
reliait pas `base` à `based`. Porter est appliqué à l'identique à la requête et
au corpus — seule leur cohérence compte. Les mots composés donnent aussi leur
forme soudée (`side-loading` → `sideload`), et un petit lexique de jargon
d'analyste (`creds`, `exfil`, `privesc`, `rce`, `lolbin`, `2fa`) est traduit
**côté requête uniquement**, le corpus employant déjà le vocabulaire canonique.

**Les mots sont pondérés par leur rareté (IDF).** `windows` ou `file`
apparaissent partout et ne discriminent rien ; `kerberoasting` désigne une
seule chose. Le vocabulaire indexé compte 4 672 racines.

**Les entités nommées et les tactiques servent d'indices.** Les noms et alias
des groupes, software et campagnes — 1 775 libellés — favorisent les techniques
qu'ils utilisent réellement, avec l'entité citée comme preuve. Les noms de
tactiques font de même :

```
search_techniques("lateral movement rdp")
→ T1021.001 0.758  matched: {"alias": ["rdp"], "tactic": ["later", "movement"]}
  tactics_in_query: [{"id": "TA0008", "name": "Lateral Movement"},
                     {"id": "TA0109", "name": "Lateral Movement"}]
```

Le score reste une **couverture de la requête** : chaque mot compte une fois,
au meilleur poids obtenu, et le résultat est borné à 1. Un mot trouvé dans le
nom ou dans un acronyme vaut 1, dans le nom de la parente 0,8, via une entité
0,8, via une tactique 0,6, dans la description 0,35.

À score égal, le **départage** est déterministe et explicité : nom exactement
égal à la requête, puis nom le mieux couvert par la requête, puis **technique
parente avant sous-technique** (règle de précision CISA/MITRE, inchangée depuis
la v2.1), puis nom le plus court, puis identifiant.

`search_internal` suit exactement le même chemin de code : les deux recherches
appellent toujours le même `_lexical_score`, comme en v2.1 — la promesse
« mêmes règles que la recherche MITRE » reste vraie par construction. Faute de
corpus pour calculer une rareté sur quelques fiches, chaque mot y pèse 1 : la
formule retombe à l'identique sur celle de la v2.1.

## 6. Filtres `platform` et `tactic` validés, limite réglable

Le filtre `matrix` levait déjà une erreur explicite en v2.1. Les deux autres
non : `platform="windowz"` renvoyait **zéro résultat en silence** — et zéro
résultat, dans ce serveur, a un sens précis et documenté, « pas de mapping »,
qui est une conclusion d'analyse. Une faute de frappe était donc lue comme un
verdict.

```
search_techniques("phishing", platform="windowz")
→ "platform inconnue 'windowz' : attendu une valeur parmi Containers, ESXi, ..."

search_techniques("phishing", tactic="credential acces")
→ "tactic inconnue 'credential acces' : attendu un id TAxxxx, un nom ou un
   shortname parmi collection, command-and-control, credential-access, ..."
```

Le filtre `tactic` accepte maintenant les trois formes : identifiant
(`TA0006`), shortname (`credential-access`) ou nom (`Credential Access`).

`get_datasources` reçoit un paramètre `limit` (60 par défaut, 300 au maximum)
pour élargir la liste sans changer d'outil ; le total exact et le drapeau
`truncated` restent rendus :

```
get_datasources("Process Creation", limit=200)
→ "techniques": {"count": 476, "items": [... 200 ...], "truncated": true}
```

## 7. Journal d'audit : les trois phases du cycle de vie MCP

La v2.1 journalisait déjà, par thread dédié et sans jamais bloquer une réponse.
Mais un appel d'outil s'y résumait à `tool_call` / `success` : impossible de
reconstituer une session, de mesurer une latence, ou de savoir ce que le modèle
avait réellement demandé.

```jsonl
{"ts":"...","run_id":"33c63f0cc6fc","event":"initialize","transport":"stdio","req_id":0,"protocol_requested":"2025-06-18","protocol_negotiated":"2025-06-18","client":"claude-desktop"}
{"ts":"...","run_id":"33c63f0cc6fc","event":"tools_list","transport":"stdio","req_id":1,"tool_count":18,"duration_ms":0}
{"ts":"...","run_id":"33c63f0cc6fc","event":"tool_call","transport":"stdio","req_id":13,"tool":"search_techniques","status":"success","duration_ms":3,"args":{"query":"lateral movement rdp","limit":"2"},"result":{"bytes":1195,"result_count":2,"total_matches":114,"top_score":0.758,"top_id":"T1021.001"}}
{"ts":"...","run_id":"33c63f0cc6fc","event":"server_stop","transport":"stdio"}
```

- **`run_id`** sur chaque ligne : une session se reconstitue même si plusieurs
  instances écrivent dans le même fichier.
- **Les trois phases MCP sont tracées** — `initialize` (avec la version de
  protocole demandée, celle négociée et l'identité du client), `tools_list`,
  `tool_call`. `tools_list` compte, parce que c'est par cet appel que le modèle
  découvre les outils et **lit leurs descriptions**.
- **`tool_call` enrichi** : identifiant de requête, durée en millisecondes,
  arguments en clair tronqués à 512 caractères, et un résumé non sensible du
  résultat — volume, nombre de candidats, meilleur score, identifiant en tête.
  De quoi mesurer la qualité du mapping dans la durée sans relire les réponses.
- **Un appel à un outil inexistant** est journalisé `status: "unknown_tool"` :
  c'est la signature d'une hallucination d'outil, et il faut pouvoir la compter.
- **Les erreurs de protocole** laissent une trace, transport compris.
- **Les pertes sont comptées, jamais tues** : si la file d'audit sature, une
  ligne `audit_dropped` publie le compteur.

## 8. Transport HTTP local — `--http`

Ajout strictement additif : le moteur de mapping, les outils et le routeur de
protocole sont ceux du mode stdio, appelés avec `transport="http"` ; le journal
distingue les deux par ce champ. Le mode existe pour les clients qui ne parlent
pas stdio — n8n, dont le nœud MCP attend SSE ou HTTP Streamable.

```bash
python mcp_mitre.py --http                  # 127.0.0.1:8733 par défaut
curl http://127.0.0.1:8733/healthz
→ {"status":"ok","version":"2.2.0","transport":"http","run_id":"9a33f82d724c",
   "ready":true,"db_version":{"Enterprise":"19.2","ICS":"19.2"}}
```

Deux formes de dialogue sont servies, parce que les clients de l'écosystème
n'implémentent pas la même : **Streamable HTTP** (`POST /mcp` → réponse JSON,
ou trame SSE si le client ne déclare accepter que `text/event-stream` ;
`GET /mcp` → flux de notifications) et **HTTP+SSE hérité** (`GET /sse` annonce
l'URL de dépôt, puis `POST /messages`). Le serveur reste **sans état** : aucun
identifiant de session n'est exigé.

Ce mode servant plusieurs requêtes en parallèle, le remplacement de la base par
`mitre_update` et la relecture du référentiel se font désormais sous un verrou
unique : aucune requête ne peut voir une base à moitié échangée ni un
référentiel vide le temps de sa relecture.

## 9. Robustesse du transport

- **Messages multi-lignes acceptés.** La v2.1 lisait ligne par ligne et
  **ignorait en silence** tout JSON invalide : un message pretty-printé n'était
  jamais compris, et le client attendait une réponse qui ne venait pas. Le
  serveur assemble maintenant les messages multi-lignes dans un tampon borné à
  1 Mo, répond `-32700 Parse error` à ce qui reste illisible, et traite
  immédiatement une ligne valide reçue pendant l'assemblage.
- **Enveloppes JSON-RPC validées** — message non-objet, `params` non-objet, nom
  d'outil non textuel, `arguments` non-objet — avec une erreur explicite au
  lieu du silence.
- **Arguments vérifiés avant exécution**, contre le schéma déclaré de l'outil :
  `argument inconnu : matrix (attendus : id)` au lieu du `TypeError` Python
  reformulé de la v2.1.
- **`initialize` négocie** la version de protocole : celle demandée est rendue
  si elle figure parmi `2024-11-05`, `2025-03-26` et `2025-06-18`, sinon la
  plus récente connue. La v2.1 renvoyait en écho n'importe quelle version.
- **Le nettoyage des descriptions est restreint aux vraies balises HTML**
  (`<code>`, `<br>`…). Le motif de la v2.1 retirait tout ce qui se trouvait
  entre chevrons, y compris les espaces réservés des commandes (`<PID>`,
  `<username>`) qui font partie du sens du texte.

## 10. Ce qui ne change pas

Le socle v2.1 est repris tel quel, et `--test` le vérifie plutôt que de
l'affirmer :

- les **16 outils** de la v2.1 et leurs **14 alias** sont tous présents, avec
  leurs paramètres — `get_mitigations`, `internal_reload` et le filtre `statut`
  de `list_internal_techniques` compris ;
- le **référentiel interne** est servi à l'identique : lecture seule, champs
  réservés retirés d'une fiche qui les porterait, marque haute monotone amorcée
  par `meta.dernier_id_attribue`, chargement construit à côté et adopté
  seulement en cas de succès, `internal_extensions` remontant le long de la
  hiérarchie et à travers les révocations ;
- l'**index des sources** conserve ses libellés composites `name:channel` :
  692 libellés, et le filtre `matrix` s'y applique autant qu'aux techniques ;
- `check()` / `ready` / `ensure()` / `_purge()` restent en place : **0 anomalie
  de réciprocité, 0 référence orpheline** sur la 19.2, campagnes et équipements
  désormais inclus dans le contrôle ;
- `--test` **constate** et sort en **code 1** si KO, `--strict` rend les fiches
  écartées bloquantes, `mitre_update` ne remplace la base qu'en cas de succès
  complet ;
- `get_tactics` respecte l'ordre officiel de la kill chain, le cloisonnement
  des matrices tient, et chaque réponse rappelle `db_version`.

Pour que ces notes restent vérifiables, les comportements suivants
**existaient déjà en v2.1** et ne sont donc pas revendiqués ici : la résolution
**transitive** des révocations (seul le champ `via` est nouveau), la
redirection d'un identifiant révoqué dans `search_techniques`, l'ordre de la
kill chain de `get_tactics`, la validation du filtre `matrix`, le drapeau
`truncated` de `get_datasources`, l'encodage UTF-8 des flux, et le journal
d'audit lui-même — seul son contenu est enrichi.

## 11. Migration depuis la v2.1

Aucune rupture. Les seize outils gardent leurs noms, leurs paramètres et leurs
alias ; les réponses gagnent des champs, elles n'en perdent pas. Deux outils
sont à déclarer côté client si vous les voulez : `get_campaign` et `get_asset`
(alias `mitre_campaign`, `mitre_asset`). Une seule différence de comportement à
connaître : la négociation de `protocolVersion` décrite au §9.

```bash
python mcp_mitre.py              # serveur MCP (stdio)
python mcp_mitre.py --test       # vérifie la base, sort en code 1 si KO
python mcp_mitre.py --strict     # avec --test : anomalies du référentiel bloquantes
python mcp_mitre.py --http       # transport HTTP local
```
