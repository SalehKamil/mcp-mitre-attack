# Serveur MCP MITRE ATT&CK — v2.2.1

Serveur MCP exposant les matrices **Enterprise** et **ICS** d'ATT&CK, en
**lecture seule**, pour ancrer le mapping d'un modèle de langue dans un fait
exact plutôt que dans sa mémoire.

Un seul fichier, `mcp_mitre.py`, sans aucune dépendance hors bibliothèque
standard Python. Deux transports : **stdio** (client MCP classique) et **HTTP
local** (clients qui ne parlent pas stdio, n8n par exemple).

---

## 1. Démarrer

```bash
python mcp_mitre.py --test      # vérifie la base, sort en code 1 si KO
python mcp_mitre.py             # serveur MCP sur stdio
python mcp_mitre.py --http      # serveur HTTP local, 127.0.0.1:8733
```

Au premier lancement, le serveur télécharge les deux bundles STIX depuis
`raw.githubusercontent.com/mitre-attack/attack-stix-data` — environ **56 Mo**,
puis il travaille sur le cache local. Les lancements suivants démarrent en
moins de trois secondes.

**Lancez toujours `--test` avant une campagne.** Il vérifie les releases
chargées, les liens tactique-technique, la réciprocité des index et les
références orphelines. Un code 1 signifie que la base est amputée : les
réponses resteraient plausibles et fausses, sans qu'aucune erreur ne le
signale.

### Options

| Option | Effet |
|---|---|
| `--test` | Diagnostic complet, sortie en code 1 si KO. Utilisable en intégration continue. |
| `--strict` | Avec `--test`, rend bloquantes les fiches écartées du référentiel interne. |
| `--http` | Sert le protocole en HTTP local **sans authentification**, au lieu de stdio. |
| `--host`, `--port` | Adresse et port du mode `--http` (défaut `127.0.0.1:8733`). |
| `--no-audit` | Démarre sans journal d'audit. |
| `--doc` | Affiche la documentation du module et sort. |

### Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `MITRE_CACHE` | `MITRE_DB/` à côté du script | Cache des bundles STIX |
| `MITRE_LOGS` | `Logs/` à côté du script | Journal d'audit JSONL |
| `MCP_INTERNAL_DB` | `referentiel_interne.json` | Référentiel interne (facultatif) |
| `MCP_HTTP_HOST` | `127.0.0.1` | Adresse d'écoute du mode `--http` |
| `MCP_HTTP_PORT` | `8733` | Port d'écoute du mode `--http` |

---

## 2. Les outils

Dix-huit outils, seize alias `mitre_*` et `internal_*`. Les paramètres marqués
d'une astérisque sont obligatoires.

### Mapping ATT&CK

| Outil | Paramètres | Rôle |
|---|---|---|
| `search_techniques` | `query*`, `limit`, `matrix`, `platform`, `tactic` | Recherche lexicale, score normalisé [0..1] avec preuves |
| `get_technique` | `id*` | Fiche complète : tactiques, plateformes, détection, sources, mesures, campagnes, sous-techniques |
| `get_tactics` | `matrix` | Tactiques dans l'ordre officiel de la kill chain |
| `get_tactic` | `id*`, `matrix` | Une tactique et ses techniques |
| `get_mitigations` | `technique_id*` | Contre-mesures d'une technique |
| `get_mitigation` | `id*` | Une contre-mesure et les techniques qu'elle couvre |
| `get_groups` | `technique_id`, `matrix` | Groupes d'attaquants |
| `get_group` | `id*` | Un groupe : alias, techniques, outils, campagnes |
| `get_software` | `technique_id` | Logiciels et maliciels |
| `get_campaign` | `id*` | Une campagne ATT&CK |
| `get_asset` | `id` | Équipements industriels (ICS) |
| `get_datasources` | `query*`, `matrix`, `limit` | Index des sources de journalisation |

### Référentiel interne (facultatif)

`list_internal_techniques`, `get_internal_technique`, `search_internal`,
`internal_reload`. Servent un fichier JSON de fiches maison `THQxxxx`, en
lecture seule. **Si vous n'utilisez pas ce référentiel, ne définissez pas
`MCP_INTERNAL_DB`** : le serveur démarre normalement avec zéro fiche et ces
quatre outils répondent des listes vides.

### Diagnostic

`mitre_stats` — version, releases chargées, fraîcheur du cache, compteurs.
`mitre_update` — retélécharge les deux matrices ; **ne remplace la base qu'en
cas de succès complet**, une panne réseau laisse la base précédente intacte.

---

## 3. Ce que le serveur garantit, et ce qu'il ne garantit pas

### Les garde-fous

**Lecture seule par conception.** Aucun outil n'écrit nulle part. Le
référentiel interne s'édite à la main, hors du serveur.

**Aucun identifiant inventé.** Un identifiant inconnu reste « non trouvé ». Un
identifiant révoqué est redirigé vers son remplaçant vivant, transitivement —
sur la 19.2, 158 redirections, zéro sans remplaçant. Une technique dépréciée
sans remplaçant est dite comme telle.

**Cloisonnement des matrices.** Zéro technique rattachée à la tactique d'une
autre matrice. Une matrice inconnue lève une erreur explicite au lieu de
renvoyer une liste vide ; `SCADA` et `OT` sont acceptés comme alias d'`ICS`,
`IT` comme alias d'`Enterprise`.

**Cache vérifié.** Un cache corrompu est détecté, purgé et retéléchargé, au
lieu de faire démarrer le serveur sur une base amputée.

**Journal d'audit JSONL.** Chaque appel d'outil, chaque erreur de protocole,
chaque chargement est tracé avec un `run_id` de session. Vingt-quatre types
d'événements, dont `tool_call` avec la durée, le résumé des arguments et le
résumé du résultat.

### Les limites, à connaître avant de s'en servir

**Le serveur ignore la matrice que vous attendez.** Il ne connaît que le
paramètre `matrix` que le modèle lui transmet. Sans ce paramètre, une recherche
mélange Enterprise et ICS — et 26 noms de techniques existent à l'identique
dans les deux matrices. Mesuré sur douze comportements typés : trois premiers
résultats sur douze dans la mauvaise matrice sans le paramètre, zéro avec.
**Passez systématiquement `matrix`.** Le champ `homonymes` d'une réponse
signale l'ambiguïté quand elle se produit.

**La recherche est lexicale, pas sémantique.** Mots entiers racinisés, pondérés
par leur rareté. Une requête doit décrire **un** comportement atomique en
mots-clés anglais ATT&CK — « lsass credential dumping », pas une phrase
française. Les résultats sont des *candidats* à vérifier avec `get_technique`,
pas des mappings.

**Le score est une couverture de la requête**, pas une probabilité. Un seul mot
significatif est plafonné à 0.59, une piste issue d'un seul nom de groupe ou
d'outil à 0.45 : ni l'un ni l'autre ne peut être déclaré « fort ». Le champ
`matched.pivot` marque ces pistes.

**Pas de rafraîchissement automatique.** La base est chargée au démarrage et ne
bouge plus. `mitre_stats` rapporte `cache_age_days` et un drapeau `stale`
au-delà de 30 jours, mais rien ne se met à jour tout seul : planifiez un
`mitre_update` ou un redémarrage.

**Le mode `--http` n'a aucune authentification.** N'importe quel processus
local peut appeler `mitre_update` ou lire la base. Gardez l'écoute sur
`127.0.0.1`, ne publiez ce mode sur aucune interface réseau.

---

## 4. Mode HTTP local

```bash
python mcp_mitre.py --http                 # 127.0.0.1:8733
python mcp_mitre.py --http --port 9000
```

| Route | Méthode | Rôle |
|---|---|---|
| `/healthz` | GET | Sonde : version, `ready`, `db_version`, `run_id` |
| `/mcp` | POST | Streamable HTTP — un message ou un **lot** JSON-RPC |
| `/mcp` | GET | Flux SSE de notifications, maintenu ouvert |
| `/sse` | GET | HTTP+SSE hérité : annonce `/messages` |
| `/messages` | POST | Dépôt de messages du mode HTTP+SSE hérité |

Le serveur est **sans état** : aucun identifiant de session n'est exigé. Il
émet un `Mcp-Session-Id` à l'initialisation, par politesse.

Trois détails qui font gagner du temps.

**Les lots JSON-RPC sont acceptés.** Un tableau de messages renvoie un tableau
de réponses. Quand un modèle demande trois outils dans le même tour, les trois
partent en une seule requête HTTP.

**Gardez `127.0.0.1`, pas `localhost`.** Le serveur n'écoute qu'en IPv4. Node
18 et suivants résolvent `localhost` sans réordonner les adresses, et sous
Windows `::1` sort en premier : une URL en `localhost` échoue alors en
`ECONNREFUSED` pendant que le serveur tourne.

**La file d'écoute est portée à 128 connexions.** La valeur par défaut de
`socketserver` est 5 : au-delà, le noyau réinitialise les connexions
excédentaires et le client reçoit une coupure, pas une erreur applicative.
Mesuré à 20 clients simultanés avant correction, 6 requêtes sur 40 étaient
perdues.

Protocoles MCP négociés : `2024-11-05`, `2025-03-26`, `2025-06-18`. Une version
inconnue reçoit la plus ancienne prise en charge plutôt qu'un écho.

---

## 5. Ce que la 2.2.1 corrige

Sept correctifs du moteur de mapping, sans ajout de fonctionnalité ni
changement de signature. Les chiffres ci-dessous sont mesurés sur ATT&CK 19.2.

**Tokens de deux lettres.** La 2.2.0 acceptait des tokens de deux caractères,
et aucun mot anglais de deux lettres ne figurait dans la liste d'arrêt : `to`
indexait 790 techniques sur 794, `of` 704, `or` 662. Une requête écrite en
anglais naturel embarquait jusqu'à 43 % de mots vides dans le dénominateur du
score. Pire, « on or of » sortait un candidat à **0.601**, au-dessus du seuil
« fort », sans la moindre réserve. Retour au minimum de trois caractères de la
2.1, deux seulement pour les tokens porteurs d'un chiffre (`c2`, `2fa`,
`t1003`). Gain mesuré : 0.784 au lieu de 0.706, 0.843 au lieu de 0.779 sur des
phrases d'analyste ordinaires.

**Biais ICS sur les noms homonymes.** Le dernier critère de départage était
l'identifiant, et tout identifiant ICS commençant par `T0` passait devant
n'importe quel `T1xxx` en ordre lexical. Sur les 26 noms partagés par les deux
matrices, **25 renvoyaient la technique industrielle en tête**, à score
identique 1.0 et sans aucun signal — « valid accounts » donnait T0859 avant
T1078. La matrice départage maintenant avant l'identifiant, Enterprise en
premier, et le champ `homonymes` nomme l'ambiguïté. Résultat : 1 sur 26.

**Requête d'un seul mot.** Le score étant une couverture, un seul mot trouvé
dans un nom atteignait 1.0 mécaniquement : « windows », « data », « service »
sortaient chacun trois techniques à 1.0. Plafonnées à 0.59, sauf identifiant
explicite ou nom strictement égal à la requête.

**Requête réduite à une entité.** « apt29 » attribuait exactement 0.9 — donc
« candidat fort » — à quarante techniques indiscernables, départagées par la
seule longueur de leur nom. Une piste dont la seule preuve est « une entité
nommée dans la requête utilise cette technique » est désormais plafonnée à 0.45
et marquée `matched.pivot`.

**Index des noms exacts.** Conséquence du premier correctif : T1053.002
s'appelle « At », deux caractères, aucun token — elle devenait introuvable par
son propre nom. Un index de noms exacts, indépendant de la tokenisation, ferme
le trou. Toute technique est maintenant trouvable par son nom : 0 sur 794
introuvable, 96,6 % en rang 1.

**Assemblage stdio multi-lignes.** Un message pretty-printé dont une valeur
contenait `}` était déclaré complet trop tôt, rejeté en `Parse error`, et la
requête restait **sans réponse pour son identifiant**. Les accolades sont
désormais comptées hors chaînes, guillemets échappés compris.

**Deux correctifs du référentiel interne.** `list_internal_techniques` prend un
instantané unique — un `internal_reload` concurrent en mode `--http` produisait
une liste de `null` avec un `result_count` correct, 92 fois sur 601 923 appels.
Et `search_internal` applique la même expansion de jargon que
`search_techniques` : « exfil cloud » donnait 1.0 côté MITRE et 0.5 côté
interne, ce qui déclenchait à tort la note « aucune fiche similaire ».

### Qualité mesurée après correction

Banc de 46 comportements SOC, vérité de terrain résolue à travers les
redirections :

| Mesure | Résultat |
|---|---|
| Top-1 | 38/46 |
| Top-3 | 46/46 |
| Rang 1 par nom propre | 96,6 % des 794 techniques |
| Requêtes hors sujet | score max 0,37, aucun faux positif fort |
| Latence `search_techniques` | 3,7 ms médian, 4,3 ms p95 |
| Charge HTTP | 40 requêtes parallèles en 0,44 s |
| `--test` | 0 anomalie de réciprocité, 0 référence orpheline |

---

## 6. Brancher un client

### stdio — configuration type

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "python",
      "args": ["C:/chemin/vers/mcp_mitre.py"],
      "env": { "MITRE_CACHE": "C:/chemin/vers/MITRE_DB" }
    }
  }
}
```

### HTTP — vérification en trois commandes

```bash
curl http://127.0.0.1:8733/healthz

curl -X POST http://127.0.0.1:8733/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -X POST http://127.0.0.1:8733/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
          "name":"search_techniques",
          "arguments":{"query":"lsass credential dumping","matrix":"Enterprise","limit":3}}}'
```

Pour le branchement sur le workflow d'évaluation n8n, voir
`README_mcp_n8n.md`.

---

## 7. Dépannage

**`--test` sort en code 1.** Lisez les lignes au-dessus d'`ECHEC` : elles
nomment la matrice en cause. Le plus souvent, un cache partiel — supprimez
`MITRE_DB/` et relancez.

**Le premier démarrage échoue.** Le téléchargement passe par
`raw.githubusercontent.com`. Derrière un proxy, déposez les deux fichiers
`enterprise-attack.json` et `ics-attack.json` à la main dans `MITRE_CACHE`.

**Un outil répond « Base MITRE indisponible ou incomplète ».** Le serveur
retente le téléchargement, avec une temporisation de 60 secondes entre deux
tentatives pour ne pas marteler la source. Les outils du référentiel interne et
`mitre_stats` continuent de répondre pendant ce temps.

**Les résultats mélangent Enterprise et ICS.** Le paramètre `matrix` n'a pas
été transmis. C'est la cause n°1 d'un mapping dans le mauvais univers ; voir la
section 3.

**Le mode `--http` refuse la connexion.** Vérifiez que l'URL est en
`127.0.0.1` et non `localhost` (section 4), et que le port n'est pas déjà pris.
