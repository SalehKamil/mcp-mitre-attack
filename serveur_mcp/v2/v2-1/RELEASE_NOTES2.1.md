# Release Notes — Serveur MCP MITRE ATT&CK v2.1 « référentiel interne THQ »

## Vue d'ensemble

La v2.1.0 ajoute au serveur de mapping v2.0 un **référentiel interne de 
techniques** (fiches `THQxxxx`), pensé comme une **extension de MITRE ATT&CK,
jamais un remplacement** : une fiche n'existe que si MITRE ne couvre pas le
comportement, ou le couvre de façon trop générique pour le contexte de
l'organisation.

Le serveur sert ce référentiel **en lecture seule** et outille l'agent pour le
consulter, le confronter au mapping MITRE et proposer des brouillons. La
création et la validation d'une fiche restent des actes humains.

L'**interface du moteur de mapping de la v2.0 n'est pas touchée** : aucun de
ses douze outils n'est retiré, aucune signature n'est modifiée, aucun de ses
garde-fous n'est levé. Le seul changement visible sur un outil existant est le
champ **additif** `internal_extensions` de `get_technique`, auquel s'ajoute le
champ `result_count` de `list_internal_techniques`. Des corrections de
robustesse lui sont apportées au passage — elles sont décrites au §5 et ne
modifient aucune réponse en fonctionnement nominal. Version mineure, sans
rupture.

Tous les exemples ci-dessous sont **mesurés** sur le serveur livré, chargé avec
ATT&CK 19.2 et le référentiel d'exemple fourni.

---

## 1. Le référentiel : un fichier JSON versionné par l'équipe

Le serveur charge `referentiel_interne.json` (chemin configurable via la
variable d'environnement `MCP_INTERNAL_DB`). Chaque fiche suit un gabarit
strict :

- `id` au format `THQxxxx` — numérotation **continue, jamais réutilisée**. La
  marque haute ne redescend jamais, y compris après la suppression d'une fiche ;
  la clé facultative `meta.dernier_id_attribue` la fait survivre à un
  redémarrage lorsque la fiche la plus haute a quitté le fichier ;
- `name` : **obligatoire** ;
- `description` : le comportement, et en quoi il est plus spécifique que MITRE ;
- `technique_mitre_liee` : **obligatoire dès qu'une technique MITRE proche
  existe** : la fiche reste rattachée au langage commun ATT&CK ;
- `statut` : `brouillon` ou `valide` ;
- champs libres (`tactique`, `source_cti`, `auteur`, dates) conservés tels quels.

Exemple de fiche : `THQ0001 — Phishing imitant le portail RH interne`,
rattachée à `T1566.002` (Spearphishing Link) — plus spécifique que le phishing
générique car le leurre imite un service interne précis, ce qui oriente la
détection vers la surveillance des domaines typosquattés du portail RH.

En l'absence du fichier, le serveur démarre normalement avec zéro fiche
(avertissement en log, `next_id` = `THQ0001`). Un gabarit prêt à copier est
livré sous `referentiel_interne.exemple.json`.

## 2. Contrôles au chargement : le référentiel ne peut pas se dégrader

Chaque fiche est vérifiée au démarrage. Mesuré avec un fichier de test
volontairement piégé :

```
[WARNING] Fiche interne ecartee : id invalide 'BAD-1' (format attendu THQ0000)
[WARNING] Fiche interne ecartee : id duplique THQ0001
[WARNING] Fiche interne ecartee : THQ0007 : champ 'name' absent ou vide
[WARNING] Fiche THQ0008 : statut 'nimporte_quoi' inconnu, retrograde a 'brouillon'
[WARNING] THQ0003 : technique_mitre_liee T1086 est revoquee par MITRE,
          remplacee par T1059.001
[WARNING] THQ0009 : aucune technique_mitre_liee, fiche sans ancrage ATT&CK
[WARNING] Fiche THQ0010 : champ(s) reserve(s) ignore(s) :
          db_version, lecture_seule
```

Trois principes gouvernent ces contrôles :

Rien n'est réparé au jugé. Une fiche invalide est écartée avec son motif,
jamais devinée. Un statut inconnu est toujours **rétrogradé** à `brouillon`,
jamais promu.

**Une fiche incomplète ne peut pas casser un outil MITRE.** C'est la raison
pour laquelle `name` est obligatoire : sans ce contrôle, une fiche réduite à un
identifiant ferait échouer toute réponse qui la cite, y compris celle de
`get_technique` sur la technique ATT&CK à laquelle elle est rattachée. Le
référentiel interne ne doit jamais pouvoir dégrader le mapping.

C'est aussi la raison pour laquelle les champs que le serveur produit lui-même
(`db_version`, `lecture_seule`, `error`, `note`, `anomalies`, `next_id`,
`internal_extensions`, `lien_revoque`…) sont **retirés** d'une fiche qui les
porterait, avec un avertissement les nommant : un champ libre ne peut pas
usurper un champ de réponse, ni falsifier la traçabilité, ni faire passer une
fiche valide pour une erreur.

**Les liens révoqués sont suivis, pas seulement signalés.** Si MITRE a révoqué
la technique liée depuis la rédaction de la fiche, l'avertissement donne le
remplaçant (grâce aux redirections transitives de la v2.0), la fiche est
indexée sur les **deux** identifiants, et `get_internal_technique` expose les
deux :

```
get_internal_technique("THQ0003")
→ "technique_mitre_liee":      {"id": "T1086", "name": null,
                                "note": "inconnue de la base ATT&CK chargee"},
  "technique_mitre_effective": {"id": "T1059.001", "name": "PowerShell", ...},
  "lien_revoque": {"declare": "T1086", "replaced_by": "T1059.001",
                   "remplacant_vivant": true}
```

L'équipe sait immédiatement quoi corriger dans la fiche, et en attendant la
fiche reste trouvable des deux côtés.

## 3. Quatre nouveaux outils

### `list_internal_techniques(statut?)` — vue d'ensemble + prochain identifiant

```
→ { "lecture_seule": true, "fiche_count": 2, "result_count": 2,
    "next_id": "THQ0003",
    "fiches": [ {"id": "THQ0001", "name": "Phishing imitant le portail RH
      interne", "statut": "valide", "technique_mitre_liee": "T1566.002"},
      {"id": "THQ0002", "name": "Exfiltration via le partage cloud tolere",
       "statut": "brouillon", "technique_mitre_liee": "T1567.002"} ],
    "compteurs": {...} }
```

Le bloc `anomalies` n'apparaît que lorsque le chargement en a relevé.

À appeler avant toute proposition de nouvelle fiche : numérotation correcte et
vue d'ensemble anti-doublon. La numérotation est **continue** et tient compte
des identifiants déjà attribués même quand la fiche correspondante a été
écartée ou supprimée : avec des fiches jusqu'à THQ0009, le prochain identifiant
est THQ0010, et un trou n'est jamais réutilisé — à condition que
`meta.dernier_id_attribue` soit tenue à jour, le serveur ne pouvant pas
l'écrire lui-même. Le filtre `statut` permet de lister les seules fiches
validées ; il n'agit que sur `result_count` et sur `fiches`, jamais sur
`fiche_count` ni sur les `compteurs`, qui décrivent toujours le référentiel
entier.

### `get_internal_technique(id)` — détail d'une fiche, pont vers ATT&CK

La technique MITRE liée est résolue en `{id, name, matrix, tactics}` :

```
get_internal_technique("THQ0001")
→ ..., "technique_mitre_liee": {"id": "T1566.002", "name": "Spearphishing Link",
                                "matrix": "Enterprise", "tactics": ["TA0001"]}
```

Les champs libres de la fiche (`tactique`, `source_cti`, `auteur`, dates) sont
restitués tels quels, et les anomalies détectées au chargement pour cette fiche
sont jointes à la réponse.

### `search_internal(query, limit?)` — anti-doublon obligatoire

Recherche lexicale dans les fiches, avec **exactement les mêmes règles que la
recherche MITRE**. Et cette fois la formule est littéralement partagée : les
deux recherches appellent la même fonction `_lexical_score`, il n'en existe
qu'un exemplaire dans le code. Elles ne peuvent donc pas diverger au fil des
versions, et la promesse est vraie par construction plutôt que par relecture.

```
search_internal("phishing portail RH")
→ THQ0001, score 1.0, matched: {"name": ["phish", "portail"]}
  note: "THQ0001 couvre probablement deja ce comportement : ne pas creer de doublon"
```

Un score ≥ 0,6 signifie qu'une fiche similaire existe probablement déjà. Quand
rien ne correspond, la réponse guide la suite :

```
search_internal("ransomware chiffrement sauvegardes")
→ 0 resultat, note: "aucune fiche interne similaire : une nouvelle fiche peut
   etre proposee (statut 'brouillon', id THQ0003) apres validation humaine"
```

La recherche accepte aussi un identifiant `THQxxxx` direct, pour retrouver une
fiche citée dans une conversation sans passer par la liste complète.

### `internal_reload()` — rechargement à chaud, toujours en lecture

Le cycle de vie d'une fiche se termine par une action humaine : relecture,
passage en `valide`, commit. Sans cet outil, il fallait redémarrer le client
MCP pour que le serveur en tienne compte. `internal_reload` relit le fichier
depuis le disque et rend la main avec le différentiel :

```
internal_reload()
→ {"status": "ok", "fiches_avant": 5, "fiches_apres": 6, "compteurs": {...}}
```

Le fichier n'est **jamais écrit**. Si l'édition humaine l'a temporairement
cassé, le référentiel en mémoire est conservé intact et l'erreur est renvoyée :

```
internal_reload()   # apres un JSON tronque
→ {"status": "error", "message": "Expecting property name...",
   "fiches_avant": 6, "fiches_apres": 6}
```

Le serveur continue de répondre avec les six fiches précédentes.

## 4. `get_technique` enrichi : le pont MITRE → interne

Chaque réponse de `get_technique` signale les fiches internes qui précisent la
technique consultée, via le champ additif `internal_extensions` :

```
get_technique("T1566.002")
→ ..., "internal_extensions": [
    {"id": "THQ0001", "name": "Phishing imitant le portail RH interne",
     "statut": "valide", "technique_mitre_liee": "T1566.002"} ]
```

Le champ remonte aussi le long de la hiérarchie et à travers les révocations,
deux cas où une fiche serait autrement restée invisible :

```
get_technique("T1566")      # technique PARENTE
→ ..., "internal_extensions": [ {..., "via": "T1566.002"} ]

get_technique("T1086")      # identifiant REVOQUE
→ {"redirect": true, "replaced_by": "T1059.001",
   "internal_extensions": [ {"id": "THQ0003", ...} ]}
```

L'analyste qui confirme un candidat MITRE découvre au même moment la
déclinaison interne du comportement, qu'il ait interrogé la technique exacte,
sa parente, ou un ancien identifiant.

Symétriquement, quand `search_techniques` ne renvoie **aucun candidat fort**,
sa note rappelle d'aller voir le référentiel maison :

```
note: "aucun candidat : l'absence de mapping est une conclusion valide |
       aucun candidat MITRE fort : confronter le comportement au referentiel
       interne avec search_internal (2 fiche(s))"
```

Ce rappel n'apparaît jamais quand MITRE répond bien : l'ordre prescrit reste
MITRE d'abord, interne ensuite.

## 5. Durcissements apportés au passage

Ces points sont nouveaux en v2.1 et concernent l'articulation entre les deux
bases :

- **Les outils internes ne dépendent pas de la base ATT&CK.** Un échec de
  téléchargement rendait jusqu'ici tout appel d'outil indisponible.
  `list_internal_techniques`, `get_internal_technique`, `search_internal`,
  `internal_reload`, `mitre_stats` et `mitre_update` répondent désormais même
  base vide : le référentiel maison reste consultable quand MITRE ne l'est pas.
- **`--test` couvre le référentiel interne** : compteurs, anomalies de
  chargement, et surtout la réciprocité de l'index (une fiche ancrée sur une
  technique vivante doit être retrouvée par `internal_extensions` de cette
  technique). Une incohérence d'index fait sortir en code 1.
- **`--strict`** rend les fiches écartées bloquantes en intégration continue.
  Sans ce drapeau, elles sont affichées mais tolérées, parce qu'un dépôt peut
  légitimement porter un référentiel en cours de nettoyage.
- **`mitre_stats` expose un bloc `internal`** : nombre de fiches, `next_id`,
  répartition valides/brouillons, fiches sans ancrage ATT&CK, liens révoqués,
  fiches écartées, avertissements, chemin du fichier et date de chargement.
- **Journal d'audit** : `internal_db_loaded` (avec le nombre de rejets, le
  nombre d'avertissements et le `next_id`), `internal_db_missing`,
  `internal_db_error`, `internal_reload`, `internal_reanchor`.

Les corrections suivantes ne changent **rien au fonctionnement nominal** —
aucun chiffre publié dans ces notes ne bouge, la suite de non-régression le
vérifie — mais elles ferment les chemins par lesquels la base ou une réponse
pouvait devenir incohérente sans qu'aucune erreur ne soit levée :

- **Un cache corrompu en cours de lecture ne laisse plus de résidus.**
  `_load_file` ne purgeait la matrice que lorsqu'elle ressortait *vide* du
  parsing. Un bundle au JSON valide mais portant un objet STIX malformé — un
  objet sans clé `id`, par exemple — fait échouer l'analyse **après** qu'une
  partie des objets a été collectée : la fonction signalait l'échec en laissant
  ces objets en mémoire, et le retéléchargement venait s'y ajouter. La purge est
  désormais faite sur toute sortie en échec, quel qu'en soit le point.
- **`_purge` retire les objets *et* les références vers ces objets.** Il vidait
  les tactiques, les techniques, les mitigations, les groupes, les software,
  les versions et l'ordre des tactiques, mais rien de ce qui les **cite**. Or
  un objet qui survit à la purge d'une matrice continue de désigner ceux qui
  sont partis : sur la 19.2, `_purge("ICS")` laissait 534 références
  orphelines dans l'index des sources, 16 dans `groups[*].techniques`, 110
  dans `software[*].techniques`, 1 dans `groups[*].software`, et 9
  redirections dont la cible venait de disparaître mais qui portaient encore
  `alive: true`. Chaque lecture filtrant ces références à l'affichage, aucune
  réponse n'était fausse — mais `mitre_stats` et `--test` comptaient des
  fantômes, et le ré-ancrage du référentiel interne pouvait résoudre un lien
  révoqué vers une technique absente. La purge est désormais complète et
  déréférence dans les deux sens : `_purge("ICS")` fait 692 → 668 libellés et
  158 → 149 redirections, **zéro orpheline**, et purger les deux matrices
  laisse une base rigoureusement vide. Le cycle reste idempotent : purger puis
  recharger ICS restitue l'état d'origine à l'identique sur les quinze
  compteurs mesurés.

- **`--test` détecte désormais cette classe de défaut.** À côté du contrôle de
  réciprocité, un contrôle de **références orphelines** parcourt toutes les
  relations et compte celles qui pointent vers un objet absent de la base, y
  compris une redirection marquée vivante dont la cible a disparu. La ligne
  `Integrite` porte les deux nombres, et une orpheline fait sortir en code 1.
  C'est la seule chose qui révèle une purge incomplète, puisque par
  construction elle ne produit aucune erreur.

- **`get_datasources` applique le filtre `matrix` aux libellés.** Il ne le
  posait que sur les techniques : `get_datasources("Windows", matrix="ICS")`
  annonçait `source_count: 37` et listait des canaux `WinEventLog:*` sous
  `matrix_filtre: ICS`, pour 4 techniques seulement. Un modèle lisant
  `matched_sources` en concluait que ces canaux Windows sont des sources de
  logs industrielles. Un libellé n'est maintenant retenu que s'il observe au
  moins une technique de la matrice demandée (3 libellés, 4 techniques). Sans
  filtre, les chiffres publiés sont inchangés.

- **`fiche_count` ne désigne plus deux nombres dans la même réponse.** Dans
  `list_internal_techniques`, la clé racine valait le nombre de fiches *après*
  filtrage pendant que `compteurs.fiche_count` valait le total : avec
  `statut="valide"`, la même réponse portait 1 et 2. `fiche_count` désigne
  désormais toujours la taille du référentiel, et le nombre de fiches
  renvoyées s'appelle `result_count`, comme dans les deux outils de recherche.

- **Un fichier qui disparaît est traité comme un fichier illisible.** Un JSON
  tronqué préservait le référentiel en mémoire, mais un fichier *absent* le
  vidait à zéro avec un simple avertissement — alors qu'une édition non
  atomique, un `git checkout` ou un `git stash` passe par un instant sans
  fichier. Les deux cas préservent maintenant l'état précédent. Seul le tout
  premier chargement accepte l'absence et démarre avec zéro fiche, un dépôt
  sans référentiel restant un cas légitime.

- **L'absence de `meta.dernier_id_attribue` est signalée.** La marque haute est
  monotone en mémoire, mais elle se perd au redémarrage si la fiche la plus
  haute a quitté le fichier, et redémarrer le client MCP est un geste
  quotidien : sans cette clé, un identifiant retiré **est** réattribué à un
  autre comportement, ce qui contredit la règle la plus forte du référentiel.
  Le serveur ne peut pas écrire la clé, il la réclame donc : son absence, ou un
  format illisible, produit un avertissement nommé dans `anomalies`, dans le
  log et dans `--test`. Le référentiel d'exemple livré la porte désormais.

## 6. Ce qui ne change pas

Hormis les deux corrections de robustesse du §5, le moteur v2.0 est repris tel
quel, et la suite de tests le vérifie explicitement plutôt que de l'affirmer :

- les **12 outils** de mapping et les **10 alias** `mitre_*` de la v1.1 sont
  tous présents, avec leurs paramètres (`matrix`, `platform`, `tactic`) ;
- la **racinisation symétrique** est intacte : `lsass` ne s'écrase pas sur
  `lsa`, `access` n'est pas coupé, `service` et `services` convergent, donc
  `windows services` renvoie bien T1543.003 en tête à 1.0 ;
- les **révocations en chaîne** restent résolues transitivement : sur la 19.2,
  158 redirections et **0 sans remplaçant vivant** ;
- l'**index des sources** conserve ses libellés composites `name:channel` :
  692 libellés, `EventCode` renvoie 58 sources, `auditd:SYSCALL` en renvoie 32 ;
- une **matrice inconnue lève une erreur explicite** au lieu de renvoyer zéro
  résultat silencieux, et `SCADA` reste accepté comme alias d'`ICS` ;
- `mitre_update` **ne remplace la base qu'en cas de succès complet** : après un
  échec réseau simulé, les 794 techniques sont toujours là et les outils
  répondent ;
- un **cache corrompu est détecté et retéléchargé** au lieu de faire démarrer
  le serveur sur une base amputée ;
- `get_tactics` respecte l'**ordre officiel de la kill chain** lu dans l'objet
  matrice publié par MITRE, et non l'ordre des identifiants ;
- le **cloisonnement des matrices** tient : zéro technique rattachée à la
  tactique d'une autre matrice, neuf homonymes détectés et signalés, `SCADA`
  accepté comme alias d'`ICS` ;
- les **outils internes et `mitre_stats` répondent base ATT&CK vide**, et
  chaque réponse porte son `db_version`, y compris sur requête vide.

## 7. Méthode et garde-fous

- **Lecture seule par conception.** Aucun outil d'écriture n'est exposé :
  l'ajout ou la validation d'une fiche passe par l'édition humaine du fichier
  JSON, versionné par l'équipe. `next_id` sert uniquement à proposer des
  brouillons correctement numérotés — le serveur n'intègre jamais rien
  lui-même, ce qui empêche un LLM de polluer le référentiel avec des fiches
  inventées.
- **Le serveur n'invente jamais d'identifiant.** Un identifiant MITRE inconnu
  reste « non trouvé » (ou redirigé s'il est révoqué) ; les identifiants
  `THQxxxx` ne sont pas des identifiants MITRE et ne s'y substituent jamais :
  `technique_mitre_liee` maintient l'ancrage ATT&CK de chaque fiche.
- **Ordre de recherche prescrit** : MITRE d'abord (`search_techniques`),
  référentiel interne ensuite (`search_internal`) — l'interne étend, il ne
  remplace pas.
- **Traçabilité conservée** : toutes les réponses des outils internes rappellent
  `db_version`, y compris sur requête vide, et le chargement du référentiel est
  tracé dans l'audit JSONL.
