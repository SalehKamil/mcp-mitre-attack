# Serveur MCP MITRE ATT&CK — v2.2.2

Serveur MCP exposant les matrices **Enterprise** et **ICS** d'ATT&CK, en
**lecture seule**, pour ancrer le mapping d'un modèle de langue dans un fait
exact plutôt que dans sa mémoire. Il sert aussi un **référentiel interne** :
les techniques propres à l'organisation, et les rapports CTI internes
rattachés aux techniques ATT&CK existantes.

Un seul fichier, `mcp_mitre.py`, lancé par **`uv run`** : aucune installation
de Python, aucune dépendance. `uv` fournit l'interpréteur, le serveur n'utilise
que la bibliothèque standard. Deux transports : **stdio** (client MCP
classique) et **HTTP local** (clients qui ne parlent pas stdio, n8n par
exemple).

---

## 1. Démarrer

Seul prérequis : **uv**.

```bash
# Linux, macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Puis :

```bash
uv run mcp_mitre.py --test      # vérifie la base, sort en code 1 si KO
uv run mcp_mitre.py             # serveur MCP sur stdio
uv run mcp_mitre.py --http      # serveur HTTP local, 127.0.0.1:8733
```

Le fichier porte ses métadonnées de script en tête (PEP 723) : Python 3.10 ou
plus, aucune dépendance. `uv` réutilise un interpréteur compatible déjà
présent, ou en télécharge un au premier lancement. Sous Linux et macOS, le
fichier est aussi exécutable directement, `./mcp_mitre.py --test`, par son
shebang `uv run --script`.

Le choix de l'interpréteur ne change rien aux réponses. Mesuré sur 2 570
appels, les réponses sont identiques à l'octet sous Python 3.10, 3.11, 3.12
et 3.13.

Au premier lancement, le serveur télécharge les deux bundles STIX depuis
`raw.githubusercontent.com/mitre-attack/attack-stix-data` — environ **56 Mo**,
puis il travaille sur le cache local. Les lancements suivants démarrent en
moins de trois secondes.

**Lancez toujours `--test` avant une campagne.** Il vérifie les releases
chargées, les liens tactique-technique, la réciprocité des index — y compris
ceux du référentiel interne — et les références orphelines. Un code 1 signifie
que la base est amputée : les réponses resteraient plausibles et fausses, sans
qu'aucune erreur ne le signale.

### Options

| Option | Effet |
|---|---|
| `--test` | Diagnostic complet, sortie en code 1 si KO. Utilisable en intégration continue. |
| `--strict` | Avec `--test`, rend bloquantes les entrées écartées du référentiel interne (fiches et références). |
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

Quand des rapports internes sont rattachés à une technique, `get_technique`
et `search_techniques` ajoutent la clé `references_internes`, **en dernier et
seulement dans ce cas** : sans rattachement, leur réponse est celle de la
v2.2.1 à l'octet.

### Référentiel interne (facultatif)

| Outil | Paramètres | Rôle |
|---|---|---|
| `search_internal` | `query*`, `limit`, `matrix` | Cherche fiches, rapports et candidats MITRE ; rend une `proposition` avec le bloc à coller |
| `get_internal_technique` | `id*` | Une fiche `THQxxxx`, ou les rapports internes d'une technique ATT&CK (`T0846`) |
| `list_internal_techniques` | `statut` | Toutes les fiches, la partie `references_mitre`, le prochain identifiant libre |
| `internal_reload` | — | Relit le fichier sans redémarrer le serveur |

**Si vous n'utilisez pas ce référentiel, ne définissez pas
`MCP_INTERNAL_DB`** : le serveur démarre normalement avec zéro fiche et ces
quatre outils répondent des listes vides. Voir la section 3.

### Diagnostic

`mitre_stats` — version, releases chargées, fraîcheur du cache, compteurs.
`mitre_update` — retélécharge les deux matrices ; **ne remplace la base qu'en
cas de succès complet**, une panne réseau laisse la base précédente intacte.

---

## 3. Le référentiel interne

Un fichier JSON versionné par l'équipe, **servi en lecture seule**. Le serveur
ne l'écrit jamais : il propose, l'analyste écrit.

### Deux parties

```json
{
  "meta": {"dernier_id_attribue": "THQ0001", "...": "..."},
  "techniques": [
    {"id": "THQ0001", "name": "...", "description": "...",
     "statut": "brouillon", "technique_mitre_liee": "T0846",
     "references": [{"titre": "CTI-2026-041 Passerelles Modbus",
                     "lien": "https://intranet.hq/cti/2026-041"}]}
  ],
  "references_mitre": [
    {"technique_mitre": "T0846",
     "references": [{"titre": "CTI-2026-038 Reconnaissance OT site Nord",
                     "lien": "https://intranet.hq/cti/2026-038",
                     "date": "2026-08-31",
                     "commentaire": "balayage du port 502"}]}
  ]
}
```

| Partie | Pour quoi | Identifiant |
|---|---|---|
| `techniques` | Un comportement qu'ATT&CK ne couvre pas, ou trop génériquement | `THQxxxx`, saisi par l'analyste au prochain identifiant libre |
| `references_mitre` | Des rapports internes sur une technique ATT&CK **existante** | l'identifiant ATT&CK lui-même, une entrée par technique |

La base MITRE téléchargée n'est **jamais** modifiée : la liaison vit dans ce
fichier. Une **référence** est `{titre, lien}`, tous deux obligatoires, plus
`date` et `commentaire` en option.

### Le geste quotidien

1. **Chercher.** `search_internal` avec le comportement, le nom de la
   technique, ou le titre ou le lien du rapport. Passez `matrix`.
2. **Lire `proposition.type`** :

   | Type | À faire |
   |---|---|
   | `rapport_deja_reference` | Rien : le rapport est déjà rattaché |
   | `rattacher_a_mitre` | Confirmer la technique avec `get_technique`, coller `a_coller` dans `references_mitre` |
   | `rattacher_a_fiche` | Coller la référence dans la fiche THQ indiquée |
   | `a_departager` | Vérifier `candidats_a_verifier` ; puis `si_mitre_couvre` ou `sinon_nouvelle_fiche` |
   | `nouvelle_fiche` | Saisir la fiche à `id_propose`, remonter `meta.dernier_id_attribue` |
   | `verification_mitre_impossible` | Ne rien créer : la base MITRE n'est pas chargée |

3. **Coller** le bloc à l'`emplacement` indiqué, faire relire, commiter.
4. **`internal_reload`**.

MITRE passe toujours avant l'interne : une fiche THQ ne se crée que pour un
comportement qu'ATT&CK ne couvre pas. Un score faible ne suffit pas à le
conclure, d'où le type `a_departager`.

### Retrouver plus tard

- **Par le rapport** : `search_internal("CTI-2026-038")` rend le rapport et la
  technique à laquelle il est rattaché. Un titre ou un lien exact vaut 1.0.
- **Par la technique** : `get_internal_technique("T0846")` rend tous les
  rapports internes de T0846 — ceux de `references_mitre` et ceux des fiches THQ
  ancrées dessus, avec leur `source`.
- **Depuis le mapping** : `get_technique("T0846")` porte `references_internes`.

### Contrôles au chargement

Une entrée invalide est **écartée avec son motif**, jamais réparée au jugé ; une
référence invalide est écartée seule, sans emporter sa fiche. Doublons
d'entrée, identifiant `THQ` dans `references_mitre`, format d'identifiant,
entrée sans référence valide : rejet. Technique révoquée : rattachée au
remplaçant vivant, avec un avertissement. Technique inconnue de la base :
avertissement. Tout est listé par `--test`, et `--strict` rend les rejets
bloquants.

---

## 4. Ce que le serveur garantit, et ce qu'il ne garantit pas

### Les garde-fous

**Lecture seule par conception.** Aucun outil n'écrit nulle part. Le
référentiel interne s'édite à la main, hors du serveur ; `search_internal`
fournit le bloc à coller, pas l'écriture.

**Aucun identifiant inventé.** Un identifiant inconnu reste « non trouvé ». Un
identifiant révoqué est redirigé vers son remplaçant vivant, transitivement —
sur la 19.2, 158 redirections, zéro sans remplaçant. Une technique dépréciée
sans remplaçant est dite comme telle. La même règle s'applique aux
identifiants cités par le référentiel interne.

**Cloisonnement des matrices.** Zéro technique rattachée à la tactique d'une
autre matrice. Une matrice inconnue lève une erreur explicite au lieu de
renvoyer une liste vide ; `SCADA` et `OT` sont acceptés comme alias d'`ICS`,
`IT` comme alias d'`Enterprise`.

**Mapping isolé du référentiel interne.** Les rapports internes ont leur propre
index ; ils n'entrent jamais dans le vocabulaire ni dans la pondération de la
recherche ATT&CK. Ajouter des références ne déplace aucun score.

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
**Passez systématiquement `matrix`**, y compris à `search_internal`. Le champ
`homonymes` d'une réponse signale l'ambiguïté quand elle se produit.

**La recherche est lexicale, pas sémantique.** Mots entiers racinisés, pondérés
par leur rareté. Une requête doit décrire **un** comportement atomique en
mots-clés anglais ATT&CK — « lsass credential dumping », pas une phrase
française. Les résultats sont des *candidats* à vérifier avec `get_technique`,
pas des mappings.

**La proposition hérite de cette limite.** `search_internal` juge la couverture
ATT&CK avec le même moteur lexical. Sur un journal Modbus
`READ-DEVICE-IDENTIFICATION`, la requête « modbus read device identification »
ne sort que des candidats faibles, et la bonne technique, T0888, n'apparaît
qu'à la reformulation. C'est pourquoi la proposition est `a_departager` et non
`nouvelle_fiche` : **vérifiez et reformulez avant de créer une fiche**.

**Le score est une couverture de la requête**, pas une probabilité. Un seul mot
significatif est plafonné à 0.59, une piste issue d'un seul nom de groupe ou
d'outil à 0.45 : ni l'un ni l'autre ne peut être déclaré « fort ». Le champ
`matched.pivot` marque ces pistes.

**Pas de rafraîchissement automatique.** La base est chargée au démarrage et ne
bouge plus. `mitre_stats` rapporte `cache_age_days` et un drapeau `stale`
au-delà de 30 jours, mais rien ne se met à jour tout seul : planifiez un
`mitre_update` ou un redémarrage. Le référentiel interne, lui, se relit à chaud
par `internal_reload`, et automatiquement après un `mitre_update`.

**Le mode `--http` n'a aucune authentification.** N'importe quel processus
local peut appeler `mitre_update` ou lire la base et le référentiel interne.
Gardez l'écoute sur `127.0.0.1`, ne publiez ce mode sur aucune interface
réseau.

---

## 5. Mode HTTP local

```bash
uv run mcp_mitre.py --http                 # 127.0.0.1:8733
uv run mcp_mitre.py --http --port 9000
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

## 6. Ce que la 2.2.2 apporte

Les références CTI internes, **sans nouvel outil et sans toucher au mapping**.
Le détail, avec les mesures, est dans `RELEASE_NOTES_2_2_2.md`.

**Une partie `references_mitre`.** Les rapports internes se rattachent aux
techniques ATT&CK existantes, dans le fichier de l'équipe, sans écrire dans la
base MITRE. Les fiches THQ gagnent un champ `references`.

**Un lancement par `uv run`.** Métadonnées de script PEP 723 en tête de
fichier. Plus aucune commande `python` à taper, aucun environnement à
préparer.

**Une `proposition` dans `search_internal`.** Rapport déjà référencé,
rattachement à MITRE, rattachement à une fiche, candidats à départager ou
nouvelle fiche au prochain identifiant libre — avec le bloc JSON à coller et
son emplacement. Le moteur de `search_techniques` est appelé tel quel pour
juger la couverture ATT&CK.

**La recherche dans les deux sens.** Du titre ou du lien d'un rapport vers la
technique, par `search_internal` ; d'un identifiant ATT&CK vers ses rapports,
par `get_internal_technique`.

**Une seule sémantique change** : la `note` de `search_internal` ne propose plus
de créer une fiche quand ATT&CK couvre déjà le comportement.

### Le mapping ne bouge pas

La contrainte de la version : une évaluation faite en v2.2.1 reste valable.
Mesuré avec les deux serveurs côte à côte, en protocole MCP, sur ATT&CK 19.2 :

| Mesure | Résultat |
|---|---|
| Appels ATT&CK, référentiel réel | 3 409 / 3 409 identiques à l'octet |
| Appels ATT&CK, référentiel rempli de rapports | 0 écart hors `references_internes` |
| Échantillons Modbus S000–S002 | 27 / 27 identiques à l'octet |
| F1 sur les trois échantillons | identique entre versions, pour chaque règle de prédiction |
| `tools/list`, douze outils ATT&CK | identique |
| Python 3.10, 3.11, 3.12, 3.13 via `uv run` | 2 570 / 2 570 réponses identiques à l'octet |
| Lignes de la v2.2.1 modifiées dans le moteur de score | 0 |

La qualité de mapping mesurée en 2.2.1 vaut donc pour la 2.2.2 : 38/46 en
top-1, 46/46 en top-3 sur le banc de 46 comportements SOC, 96,6 % des 794
techniques en rang 1 par leur nom, aucun faux positif fort sur les requêtes
hors sujet. `--test` sort en 0 anomalie de réciprocité, 0 référence orpheline.

Un coût : `search_internal` interroge MITRE une fois par appel, et passe
d'environ 0,04 ms à environ 5 ms médian. `search_techniques` est inchangée.

### Rappel de la 2.2.1

Sept correctifs du moteur de mapping : tokens alphabétiques de trois
caractères au minimum, matrice départagée avant l'identifiant avec le champ
`homonymes`, requête d'un seul mot plafonnée à 0,59, piste issue d'une seule
entité plafonnée à 0,45 et marquée `matched.pivot`, index des noms exacts,
assemblage stdio multi-lignes robuste aux accolades, et deux correctifs du
référentiel interne. Détail dans `RELEASE_NOTES_2_2_1.md`.

---

## 7. Brancher un client

### stdio — configuration type

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "uv",
      "args": ["run", "C:/chemin/vers/mcp_mitre.py"],
      "env": {
        "MITRE_CACHE": "C:/chemin/vers/MITRE_DB",
        "MCP_INTERNAL_DB": "C:/chemin/vers/referentiel_interne.json"
      }
    }
  }
}
```

### HTTP — vérification en quatre commandes

```bash
curl http://127.0.0.1:8733/healthz

curl -X POST http://127.0.0.1:8733/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -X POST http://127.0.0.1:8733/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
          "name":"search_techniques",
          "arguments":{"query":"lsass credential dumping","matrix":"Enterprise","limit":3}}}'

curl -X POST http://127.0.0.1:8733/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
          "name":"search_internal",
          "arguments":{"query":"Remote System Discovery","matrix":"ICS"}}}'
```

Si le client MCP ne trouve pas `uv`, donnez son chemin complet dans
`command` — `where uv` sous Windows, `which uv` ailleurs. Les messages de `uv`
partent sur la sortie d'erreur : le flux stdio du protocole reste propre.

Pour le branchement sur le workflow d'évaluation n8n, voir
`README_mcp_n8n.md`.

---

## 8. Dépannage

**`--test` sort en code 1.** Lisez les lignes au-dessus d'`ECHEC` : elles
nomment la matrice ou l'entrée du référentiel en cause. Le plus souvent, un
cache partiel — supprimez `MITRE_DB/` et relancez.

**`uv` est introuvable.** Installez-le (section 1), puis ouvrez un nouveau
terminal : l'installeur ajoute `uv` au `PATH` des sessions suivantes.

**Le premier démarrage échoue.** Deux téléchargements peuvent être en cause.
Les bundles ATT&CK passent par `raw.githubusercontent.com` : derrière un proxy,
déposez les deux fichiers `enterprise-attack.json` et `ics-attack.json` à la
main dans `MITRE_CACHE`. L'interpréteur, si aucun Python 3.10 ou plus n'est
présent, est téléchargé par `uv` depuis GitHub : faites-le une fois à l'avance
avec `uv python install 3.12`, ou pointez `UV_PYTHON_INSTALL_MIRROR` vers un
miroir interne.

**Un outil répond « Base MITRE indisponible ou incomplète ».** Le serveur
retente le téléchargement, avec une temporisation de 60 secondes entre deux
tentatives pour ne pas marteler la source. Les outils du référentiel interne et
`mitre_stats` continuent de répondre pendant ce temps ; `search_internal`
répond alors `verification_mitre_impossible` et ne propose aucune fiche.

**Les résultats mélangent Enterprise et ICS.** Le paramètre `matrix` n'a pas
été transmis. C'est la cause n°1 d'un mapping dans le mauvais univers ; voir la
section 4.

**Un rapport ajouté n'apparaît pas.** Appelez `internal_reload` après avoir
enregistré le fichier. S'il n'apparaît toujours pas, `list_internal_techniques`
liste les `anomalies` : référence sans `titre` ou sans `lien`, entrée en double
pour la même technique, identifiant inconnu de la base chargée.

**`search_internal` propose `a_departager` pour un comportement connu.** Le
moteur lexical n'a trouvé que des candidats faibles. Reformulez avec le
vocabulaire ATT&CK et l'artefact le plus discriminant, puis vérifiez les
candidats avec `get_technique` avant de créer une fiche.

**Le mode `--http` refuse la connexion.** Vérifiez que l'URL est en
`127.0.0.1` et non `localhost` (section 5), et que le port n'est pas déjà pris.
