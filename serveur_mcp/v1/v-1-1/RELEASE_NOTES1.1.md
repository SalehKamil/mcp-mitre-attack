# Release Notes — MCP MITRE ATT&CK v1.1.0

## Vue d'ensemble

La v1.0 exposait la seule matrice Enterprise. La v1.1 lui ajoute **ATT&CK for ICS** dans la même base, pensée pour la convergence IT/OT : un agent peut désormais traiter dans une même conversation une intrusion bureautique et une manipulation de procédé industriel, sans que les deux mondes se contaminent.

Trois évolutions structurent cette version :

1. la **fusion Enterprise + ICS** dans une base unique, cloisonnée par matrice ;
2. la **traçabilité** des usages du serveur, via un journal d'audit JSONL ;
3. l'**explicitation des correspondances** dans la recherche, pour que le modèle puisse juger la solidité d'un candidat avant de le retenir.

Tout l'acquis fonctionnel de la v1.0 est conservé : pipeline de détection, résolution par nom et alias, normalisation des identifiants, ordre kill-chain officiel, métadonnées de troncature, cache atomique, démarrage asynchrone. Le transport reste **stdio local**, sans couche réseau ni sécurité : elles sont réservées au jalon production.

---

## Base hybride Enterprise + ICS

### Les identifiants ICS sont reconnus

La v1.0 ne retenait que les phases dont `kill_chain_name` valait `mitre-attack` et ne résolvait les identifiants que depuis la source `mitre-attack`. Ces deux filtres écartaient mécaniquement l'intégralité du domaine ICS, publié sous `mitre-ics-attack`. Ils acceptent désormais les deux sources. Une technique OT s'interroge exactement comme une technique IT :

```
mitre_technique("T0831")
→ { "id": "T0831", "name": "Manipulation of Control", "matrix": "ICS", ... }
```

La base fusionnée compte **27 tactiques** (15 Enterprise + 12 ICS), **794 techniques** (697 + 97), 178 groupes APT, 831 logiciels et **96 mitigations** (44 + 52). Chaque tactique, technique et mitigation porte un champ `matrix` indiquant sa matrice d'origine.

### Rattachement tactique cloisonné par matrice

Les tactiques Enterprise et ICS partagent des `shortname` STIX identiques : `initial-access`, `persistence`, `execution` et `lateral-movement` existent des deux côtés. Le lien technique vers tactique est donc établi **au sein de la matrice de la technique**, jamais par simple correspondance de nom court. Sans ce cloisonnement, la fusion produirait des rattachements croisés, c'est-à-dire des mappings faux au niveau tactique.

Exemple, la tactique « Persistence » existe dans les deux matrices sous deux identifiants différents mais avec le même nom court :

```
TA0003 = Persistence (Enterprise) — 113 techniques
TA0110 = Persistence (ICS)        —  10 techniques
```

Cette homonymie étant une source d'erreur pour un modèle qui raisonne sur des noms, `mitre_tactic` accepte un argument `matrix` pour lever l'ambiguïté et signale systématiquement le jumeau via un champ `homonyme_autre_matrice`.

Le rattachement s'effectue après indexation complète des deux bundles, au même titre que les relations. L'ordre dans lequel MITRE publie ses objets n'a donc aucune influence, et celui dans lequel les deux matrices sont chargées non plus. Le diagnostic `--test` vérifie explicitement que le nombre de liens reconstruits est non nul et sort en erreur dans le cas contraire.

### Fusion des groupes et logiciels communs aux deux matrices

Les techniques, tactiques et mitigations occupent des espaces d'identifiants disjoints entre les deux domaines : `T1***` contre `T0***`, `TA00**` contre `TA01**`, `M1***` contre `M0***`. Les groupes et les logiciels, eux, partagent leurs identifiants `G****` et `S****` et sont publiés sous le même identifiant STIX dans les deux bundles. Douze groupes et dix-sept logiciels sont ainsi présents deux fois.

Ces objets sont **fusionnés**. La seconde occurrence enrichit la liste `matrices` de l'entrée existante sans recréer l'objet, ce qui préserve les relations déjà collectées lors du premier passage. Ce sont précisément les acteurs hybrides qui sont concernés, ceux dont l'analyse IT/OT a le plus besoin :

```
mitre_group("Sandworm Team")
→ { "id": "G0034", "matrices": ["Enterprise", "ICS"],
    "techniques": { "shown": 50, "total": 82, "truncated": true }, ... }
```

Les groupes et logiciels portent donc un champ `matrices` qui est une **liste**, là où les tactiques, techniques et mitigations portent un champ `matrix` qui est une **chaîne**. La distinction est volontaire. Une valeur composite du type `"Enterprise+ICS"` aurait obligé le modèle à interpréter une troisième valeur non documentée, alors que la consigne d'analyse lui demande précisément de ne jamais mélanger les deux mondes. Chaque technique retournée dans la fiche d'un groupe est par ailleurs annotée de sa propre matrice.

### Ordre kill-chain par matrice

La v1.0 lisait l'ordre canonique des tactiques dans l'objet `x-mitre-matrix` publié plutôt que de le coder en dur. Les deux domaines ayant chacun leur matrice officielle et leur propre progression, `mitre_tactics` restitue désormais chaque ensemble dans son ordre, et accepte un filtre `matrix`.

---

## Détection étendue au domaine industriel

Le pipeline de détection de la v1.0 s'appuie sur les objets `x-mitre-detection-strategy`, `x-mitre-analytic` et `x-mitre-data-component`, qui portent les sources de journalisation et les canaux exploitables, et non sur les champs hérités `x_mitre_data_sources` et `x_mitre_detection`, vides depuis plusieurs versions d'ATT&CK.

Ce modèle est renseigné dans le domaine ICS au même titre que dans Enterprise : 97 stratégies de détection, 97 analytics et 36 composants de données y sont publiés. Le pipeline s'applique donc à l'OT sans modification.

Résultat sur la base fusionnée : **794 techniques sur 794 disposent d'au moins une stratégie de détection**, et 737 portent des sources de données ou des canaux exploitables (652 Enterprise, 85 ICS). L'index inverse compte **2796 libellés** de sources, composants et canaux.

Un détail de qualité de données propre à l'ICS est traité au passage : certains canaux y valent littéralement la chaîne `"None"`, ce qui produirait des libellés parasites du type `Asset:None` dans l'index. Ces valeurs sont filtrées au chargement.

`mitre_datasources` couvre en conséquence les deux matrices, et accepte un filtre `matrix`.

---

## Recherche scorée avec preuves de correspondance

`mitre_search` conserve la pondération de la v1.0, qui porte sur l'identifiant, le nom, la description, les sources de données, les canaux de journalisation et le texte des analytics. Un `4688`, un `WinEventLog:Security` ou un nom de binaire restent des requêtes valides, et la recherche s'étend maintenant au vocabulaire industriel.

Trois apports s'y ajoutent.

Chaque candidat porte un champ **`matched_in`** indiquant où la correspondance a eu lieu : `id`, `name`, `description`, `data_source` ou `detection`. La recherche étant lexicale, un candidat peut remonter par simple coïncidence de sous-chaîne, « port » matchant « support ». Ce champ donne au modèle de quoi écarter le bruit avant même de consulter le détail. Sur une requête `modify controller tasking` restreinte à l'ICS, le bon candidat sort à 58 avec `["detection", "name"]` quand le bruit suivant plafonne à 7 avec `["description"]` seul.

Le **nombre de candidats est borné** par un argument `limit`, à 25 par défaut et 50 au maximum, pour contrôler la consommation de contexte sur des requêtes larges.

Un argument **`matrix`** restreint la recherche à un seul domaine. Il accepte `Enterprise`, `ICS`, ainsi que les formes `IT`, `OT` et `SCADA`. C'est le garde-fou direct de la phase de classification du signal : une fois le monde déterminé, la recherche ne peut plus proposer de candidats venus de l'autre.

Le tri reste déterministe, par score décroissant puis par identifiant, et la normalisation des identifiants est appliquée à la requête, `t1059.1` étant reconnu comme `T1059.001`.

---

## Journal d'audit JSONL

Tous les événements du serveur sont journalisés dans `Logs/mcp_audit.jsonl` : démarrage et arrêt, téléchargements avec leur durée, chargement du cache, détection d'un cache invalide ou incomplet, appels d'outils avec leur statut.

```
{"ts": "2026-03-20T10:44:22.442994", "event": "download_start", "matrix": "Enterprise", "url": "..."}
{"ts": "2026-03-20T10:44:29.201086", "event": "download_complete", "matrix": "Enterprise", "duration_ms": 6757}
{"ts": "2026-03-20T10:44:30.029646", "event": "server_start", "pid": 21508, "version": "1.1.0", "tools": 12}
```

L'écriture est portée par un thread dédié qui se bloque sur le premier événement puis vide la file par lots, de sorte qu'elle **ne bloque jamais** la réponse à un outil. La file est drainée intégralement à l'arrêt, l'événement `server_stop` inclus. Le writer est instancié avant la construction de la base, ce qui permet de tracer aussi les événements de chargement initial.

Le répertoire est redéfinissable par `MITRE_LOGS`, et l'option `--no-audit` désactive complètement le journal.

---

## Surface d'outils

Deux outils s'ajoutent aux onze de la v1.0, portant le total à **douze**.

`mitre_mitigation(id)` détaille une contre-mesure et la liste complète des techniques qu'elle couvre, là où `mitre_mitigations(technique_id)` part d'une technique pour lister ses contre-mesures. Les deux chemins sont utiles et complémentaires : le premier sert à élargir une recommandation, le second à la produire.

La nomenclature `mitre_*` reste la référence. Neuf **alias `get_*`** sont acceptés en entrée par compatibilité avec les intégrations qui les utilisent. Ils sont résolus au moment du dispatch et ne figurent pas dans `tools/list`, donc ne consomment aucun contexte côté modèle.

---

## Robustesse

Un **cache incomplet est refusé**. Une base n'est déclarée prête que si chacune des deux matrices attendues figure dans ses métadonnées. Un fichier illisible, tronqué, ou ne contenant qu'un seul domaine déclenche un nouveau téléchargement au lieu d'un démarrage silencieux sur une base amputée. Le risque écarté est précis : un serveur qui annoncerait deux matrices tout en n'en servant qu'une amènerait le modèle à mapper des signaux IT dans la matrice industrielle, sans qu'il puisse s'en apercevoir.

`mitre_update` **ne vide plus la base avant de télécharger**. Les deux bundles sont récupérés et analysés d'abord, la base en mémoire n'étant remplacée qu'en cas de succès complet. Un échec réseau ou de parsing laisse la base existante intacte et le signale dans la réponse via un champ `base_preservee`. Le fichier de cache continue d'être écrit par remplacement atomique.

Le **diagnostic `--test` vérifie au lieu d'afficher**. Il détaille chaque matrice séparément, puis sort en code 1 si une matrice est vide ou si le nombre de liens tactique-technique est nul. Ce contrôle est utilisable tel quel en intégration continue, et couvre la classe de régression la plus dangereuse pour ce serveur : celle qui vide silencieusement une relation sans produire la moindre erreur.

Les **erreurs d'arguments** retournent désormais, en plus du message, la liste des paramètres attendus par l'outil appelé, ce qui permet au modèle de corriger son appel sans tâtonner.

---

## Compatibilité et migration

Base téléchargée depuis `mitre/cti`, domaines Enterprise et ICS, spécification ATT&CK 3.3.0. Python 3.8 ou supérieur, bibliothèque standard uniquement.

Le fichier de cache change de nom et de contenu : `MITRE_DB/enterprise.json` devient `MITRE_DB/attack.json` et contient les deux matrices fusionnées, pour environ 5 MB. L'ancien fichier peut être supprimé. En son absence, les deux matrices sont téléchargées au premier lancement puis réutilisées, avec un rechargement à froid de l'ordre de 150 ms.

Aucun appel écrit pour la v1.0 n'est cassé. Les onze outils conservent leur nom et leur signature, les arguments ajoutés (`matrix`, `limit`) étant tous optionnels. Un appel `mitre_tactic("Persistence")` sans précision de matrice continue de répondre, en signalant l'homonyme plutôt qu'en choisissant silencieusement.

---

## Limites connues

- Domaine Mobile non couvert.
- Les campagnes (`campaign`) ne sont pas exposées, ni les ressources industrielles (`x-mitre-asset`), objets récents du domaine ICS qui décrivent les équipements ciblés. Leur exposition est un candidat naturel pour le jalon suivant.
- La recherche reste lexicale et fonctionne par sous-chaînes : « port » matche « support ». Le champ `matched_in` est la réponse apportée à cette limite dans cette version. La correspondance par mots entiers et la racinisation restent à faire.
- Le vocabulaire ATT&CK évolue, la tactique `TA0005` s'appelant désormais « Stealth » et une tactique `TA0112` « Defense Impairment » ayant été introduite. Le serveur lit ces libellés dans la base et suit donc le changement, mais les prompts rédigés sur l'ancienne nomenclature doivent être revus.
- Le cache n'expire pas automatiquement ; `mitre_stats` signale simplement qu'il a plus de 30 jours.
- Transport stdio uniquement, sans authentification ni exposition réseau.
