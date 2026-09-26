# Release Notes — Serveur MCP MITRE ATT&CK v2.2.2 « références CTI internes, mapping inchangé, lancement par uv »

## Vue d'ensemble

La v2.2.2 est une **version fonctionnelle à mapping gelé**. Elle apprend au
référentiel interne à porter les rapports CTI de l'organisation, sans ajouter
d'outil, sans retirer de garde-fou, et **sans modifier une seule réponse des
outils de mapping ATT&CK**. Les **dix-huit outils** et les **seize alias** de la
v2.2.1 sont tous là, avec leurs paramètres ; un seul paramètre optionnel
apparaît, `matrix` sur `search_internal`.

Le besoin était double. D'une part, rattacher un rapport interne à une
technique qu'ATT&CK connaît déjà, **sans écrire dans la base MITRE
téléchargée**. D'autre part, attribuer un identifiant maison à un comportement
qu'ATT&CK ne couvre pas, avec ses rapports. Et dans les deux cas, pouvoir
retrouver plus tard la technique à partir du nom du rapport, ou le rapport à
partir du nom de la technique.

La contrainte était plus forte que le besoin : **une évaluation de mapping
réalisée avec la v2.2.1 doit rester valable avec la v2.2.2**, sans être
refaite. Elle est tenue par construction et vérifiée par mesure (§6) :

- le moteur de score, la tokenisation, l'IDF, le tri et les notes de
  `search_techniques` sont ceux de la v2.2.1, à l'octet ;
- les descriptions des douze outils ATT&CK, que le modèle lit dans
  `tools/list`, sont identiques ;
- sans rapport rattaché, les réponses des outils ATT&CK sont **identiques à
  l'octet** ; avec rapport rattaché, elles gagnent une clé en dernière
  position, et toutes les autres gardent leur valeur et leur ordre.

Le serveur se lance désormais par **`uv run mcp_mitre.py`** : plus de
commande `python`, plus d'interpréteur à installer (§9).

Une seule sémantique publiée change **volontairement** : la `note` de
`search_internal` ne propose plus de créer une fiche quand MITRE couvre déjà le
comportement (§3). Aucune réponse ne perd de champ.

Tous les chiffres ci-dessous sont **mesurés** sur le serveur livré, chargé avec
ATT&CK 19.2 (Enterprise + ICS, 794 techniques, 158 redirections).

---

## 1. Un référentiel interne en deux parties

Le fichier garde sa forme ; il gagne une clé.

```json
{
  "meta": {"dernier_id_attribue": "THQ0003", "...": "..."},
  "techniques": [
    {"id": "THQ0003", "name": "...", "description": "...",
     "statut": "brouillon", "technique_mitre_liee": "",
     "references": [{"titre": "CTI-2026-060 Nouveau comportement",
                     "lien": "https://intranet.hq/cti/2026-060"}]}
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

**`techniques`** reste la partie des fiches `THQxxxx`, pour les comportements
qu'ATT&CK ne couvre pas, ou trop génériquement pour le contexte. Elle gagne un
champ optionnel `references`. `technique_mitre_liee` y désigne la technique
ATT&CK la plus proche, quand il y en a une.

**`references_mitre`** est nouvelle. Une entrée par identifiant ATT&CK
**existant**, qui ne porte que des références internes. C'est la surcouche
demandée : la base MITRE téléchargée n'est jamais modifiée, la liaison vit
dans le fichier de l'équipe.

Une **référence** est un objet `{titre, lien}`, tous deux obligatoires — le
titre pour retrouver le rapport par son nom, le lien pour l'ouvrir. `date` et
`commentaire` sont optionnels.

Un référentiel v2.2.1, sans la clé `references_mitre`, se charge **à
l'identique**.

## 2. Rattacher un rapport à une technique MITRE existante

L'entrée est rattachée à la technique par son identifiant, normalisé comme
partout ailleurs : `t0888` devient `T0888`, `T1059.1` devient `T1059.001`.
Les révocations sont suivies comme pour les fiches :

```
references_mitre : {"technique_mitre": "T1066", ...}
→ [avertissement] T1066 (references_mitre) est revoquee par MITRE,
                  remplacee par T1027.005 : references rattachees au remplacant

get_internal_technique("T1066")
→ "technique_mitre": {"id": "T1027.005", "name": "Indicator Removal from Tools"}
  "note": "'T1066' est revoquee, remplacee par T1027.005"
```

Le rapport reste donc visible depuis la technique vivante, et l'identifiant
d'origine est conservé tel que l'analyste l'a écrit.

## 3. `search_internal` propose, l'analyste écrit

Le serveur reste **en lecture seule**. `search_internal` fait désormais le
tri complet, et rend une **`proposition`** avec le bloc JSON à coller et
l'endroit où le coller. Elle confronte la requête à trois sources : les fiches
THQ (comme avant), les **rapports** des deux parties (nouveau), et **MITRE**,
via le moteur de `search_techniques` — appelé tel quel, pas copié : mêmes
candidats, mêmes scores que l'outil de mapping.

L'ordre de décision est fixe :

| `proposition.type` | Quand | Bloc rendu |
|---|---|---|
| `rapport_deja_reference` | Titre ou lien exact, ou forte ressemblance et aucune technique couvrante | aucun : rien à ajouter |
| `rattacher_a_mitre` | Candidat MITRE ≥ 0,6 | entrée `references_mitre`, ou référence à ajouter si l'entrée existe |
| `rattacher_a_fiche` | Fiche THQ ≥ 0,6 | référence à ajouter à la fiche |
| `a_departager` | Candidats MITRE faibles seulement | les deux blocs, MITRE et nouvelle fiche |
| `nouvelle_fiche` | Aucun candidat | fiche au prochain identifiant libre |
| `verification_mitre_impossible` | Base MITRE indisponible | aucun : ne rien créer avant vérification |

MITRE passe avant l'interne : une fiche THQ ne se crée que pour un
comportement qu'ATT&CK ne couvre pas.

```
search_internal("Remote System Discovery", matrix="ICS")
→ "proposition": {
    "type": "rattacher_a_mitre",
    "technique_mitre": {"id": "T0846", "name": "Remote System Discovery",
                        "matrix": "ICS", "tactics": ["TA0102"], "score": 1.0},
    "emplacement": "references_mitre > entree technique_mitre=T0846 >
                    references (ajouter a la liste)",
    "a_coller": {"titre": "<titre du rapport CTI interne>",
                 "lien": "<lien interne du rapport>",
                 "date": "<AAAA-MM-JJ, optionnel>"},
    "a_verifier": "confirmer T0846 avec get_technique avant d'ecrire ...",
    "deja_rattaches": ["CTI-2026-038 Reconnaissance OT site Nord", ...],
    "puis": "internal_reload"}
```

Deux règles méritent d'être dites, parce que les deux choix inverses
produisaient une mauvaise proposition pendant la mise au point.

**Un score faible ne prouve pas l'absence de couverture ATT&CK.** Sur un
journal Modbus `READ-DEVICE-IDENTIFICATION`, la requête « modbus read device
identification » ne fait sortir que des candidats sous 0,3 ; la bonne
technique, T0888, n'apparaît qu'à la reformulation. Proposer une nouvelle
fiche à ce stade aurait créé un doublon d'ATT&CK. La proposition est donc
`a_departager` dès qu'un candidat MITRE existe, même sous le seuil faible :

```
search_internal("modbus read device identification", matrix="ICS")
→ "type": "a_departager",
  "candidats_a_verifier": [{"id": "T0861", "score": 0.293},
                           {"id": "T0869", "score": 0.168},
                           {"id": "T0846.002", "score": 0.15}],
  "si_mitre_couvre": {...}, "sinon_nouvelle_fiche": {"id_propose": "THQ0004", ...}
```

**Une requête comportementale qui ressemble au titre d'un rapport reste une
recherche de technique.** « lsass credential dumping » ressemble à 0,667 au
titre « CTI-2026-012 Dump LSASS ». Ce n'est pas l'identification de ce rapport :
c'est le comportement, que MITRE couvre à 0,894. La proposition est
`rattacher_a_mitre` sur T1003.001, et le rapport existant apparaît dans
`deja_rattaches` pour éviter le doublon. « Déjà référencé » exige un titre ou un
lien exact, ou une forte ressemblance quand aucune technique ne couvre la
requête.

La **`note`** de `search_internal` suit la proposition. C'est le seul
changement de sémantique de la version : en v2.2.1, un référentiel vide
répondait toujours « une première fiche peut être proposée », y compris pour
un comportement qu'ATT&CK couvre à 1.0. Les notes v2.2.1 sont conservées mot
pour mot ; celles qui invitent à créer une fiche ne sont plus émises que si la
proposition va dans ce sens.

## 4. Retrouver un rapport ou une technique par son nom

La recherche fonctionne dans les deux sens, sans nouvel outil.

**Du rapport vers la technique** — `search_internal` cherche dans les titres,
liens et commentaires des références, avec la fonction de score commune. Un
titre ou un lien strictement égal vaut 1.0 :

```
search_internal("CTI-2026-038")
→ "rapports": [{"titre": "CTI-2026-038 Reconnaissance OT site Nord",
                "rattache_a": {"type": "mitre", "id": "T0846"}, ...}]
  "proposition": {"type": "rapport_deja_reference", ...}

search_internal("https://intranet.hq/cti/2026-039")
→ rattache_a T0888, score 1.0, matched: {"exact": ["lien"]}
```

**De la technique vers les rapports** — `get_internal_technique` accepte
désormais un identifiant ATT&CK, en plus d'un `THQxxxx` :

```
get_internal_technique("T0846")
→ "type_entree": "references_mitre",
  "references_internes": {"count": 3, "items": [
     {"titre": "CTI-2026-038 Reconnaissance OT site Nord", "source": "T0846"},
     {"titre": "Referentiel detection OT v3",              "source": "T0846"},
     {"titre": "CTI-2026-041 Passerelles Modbus",          "source": "THQ0001"}]}
```

Les rapports d'une fiche THQ ancrée sur T0846 remontent avec eux ; `source`
dit d'où vient chaque référence, `via` qu'elle est rattachée à une
sous-technique.

L'index des rapports est **propre au référentiel interne**. Il n'entre jamais
dans le vocabulaire ni dans l'IDF de la recherche MITRE : ajouter mille
rapports ne déplace aucun score ATT&CK.

## 5. Les outils ATT&CK ne gagnent qu'une clé

`get_technique` et `search_techniques` gagnent la clé **`references_internes`**.
Trois règles la rendent inoffensive pour un pipeline existant :

- elle n'apparaît **que si** un rapport est rattaché à la technique ;
- elle est ajoutée **en dernier**, après la `note` ;
- dans `search_techniques`, elle est calculée **après** le classement, à partir
  de `results` déjà figé : elle ne peut changer ni un score, ni un rang, ni la
  note.

```
search_techniques("remote system discovery", matrix="ICS", limit=3)
→ results : T0846 1.0 | T0888 1.0 | T0846.002 1.0     (inchange)
  "references_internes": {"T0846": {"count": 3, ...},
                          "T0888": {"count": 1, ...}}
```

Les descriptions de ces deux outils ne mentionnent pas la clé : les modifier
aurait changé ce que le modèle lit dans `tools/list`. Elle est documentée dans
celles des outils internes.

## 6. Le mapping ne bouge pas : mesuré

Les deux serveurs ont été lancés côte à côte par `uv run`, en vrai protocole
MCP sur stdio,
sur la même base 19.2, avec les mêmes appels. Deux référentiels : le
référentiel réel de l'équipe, vide, et un référentiel de test rempli exprès,
avec des rapports rattachés aux trois techniques attendues des échantillons.

| Banc | Appels | Résultat |
|---|---|---|
| Échantillons S000–S002, référentiel réel | 27 | **27 identiques à l'octet** |
| Couverture large, référentiel réel | 3 409 appels ATT&CK | **3 409 identiques à l'octet** |
| Couverture large, référentiel rempli | 3 409 appels ATT&CK | 3 227 à l'octet ; 182 avec `references_internes` en plus ; **0 écart** une fois la clé retirée |
| `tools/list`, douze outils ATT&CK | — | **identique** |
| Référentiel v2.2.1 → même fichier au format v2.2.2 | 9 | **9 identiques à l'octet** |
| v2.2.2 sous Python 3.10, 3.11, 3.13 contre 3.12, via `uv run` | 2 570 | **2 570 identiques à l'octet** |

La couverture large interroge chaque technique par son nom, avec et sans
filtre de matrice, par la première phrase de sa description, par son
identifiant — vivant, révoqué ou déprécié —, plus les tactiques, les filtres
`platform` et `tactic`, le jargon, les entités et les requêtes pathologiques
de la v2.2.1 (« on or of », « At », « apt29 », « windows »).

Sur les trois échantillons Modbus de la vérité de terrain, le F1 est
**identique entre les deux versions** quelle que soit la règle de prédiction :

| Règle de prédiction | Prédictions | F1 tactique | F1 technique |
|---|---|---|---|
| 1er résultat de la requête principale | T0846.001, T0861, T0885 | 0,333 | 0,333 |
| Meilleur 1er résultat sur deux requêtes | T0846.001, T1693.002, T0861 | 0,667 | 0,667 |
| Procédure complète de vérification des fiches | T0846, T0888, T0861 | 1,0 | 1,0 |

L'écart entre les lignes rappelle ce que le README dit du score : c'est une
file de candidats. La vérification des fiches `get_technique` fait la
différence, en particulier sur `READ-DEVICE-IDENTIFICATION`, que la fiche
T0888 nomme par la marque et le modèle.

Dans le code, **36 lignes** de la v2.2.1 sont modifiées — version, en-tête,
aide de lancement, descriptions des trois outils internes, notes de
`search_internal`, un compteur, un libellé de `--test` — et 683 sont
ajoutées. **Aucune** ne touche
`_tokens`, `_lexical_score`, `_query_weights`, le tri ou le corps de
`search_techniques` avant sa dernière ligne.

## 7. Contrôles au chargement

Même doctrine que pour les fiches : une entrée invalide est écartée avec son
motif, jamais réparée au jugé, et une référence invalide est écartée **seule**,
sans emporter la fiche ou l'entrée qui la porte.

| Cas | Niveau | Effet |
|---|---|---|
| Référence sans `titre` ou sans `lien`, ou non-objet | avertissement | référence écartée |
| Lien avec espace ou caractère de contrôle | avertissement | référence écartée |
| Même lien deux fois dans une entrée | avertissement | doublon écarté |
| Entrée `references_mitre` sans `technique_mitre` | rejet | entrée écartée |
| Identifiant au mauvais format | rejet | entrée écartée |
| Identifiant `THQxxxx` dans `references_mitre` | rejet | se déclare dans `techniques` |
| Deux entrées pour la même technique | rejet | regrouper les références |
| Entrée sans aucune référence valide | rejet | entrée écartée |
| Technique révoquée | avertissement | rattachée au remplaçant vivant |
| Technique dépréciée sans remplaçant | avertissement | conservée, à reclasser |
| Technique inconnue de la base chargée | avertissement | visible via `get_internal_technique` seulement |
| `references_mitre` n'est pas une liste | avertissement | partie ignorée, fiches intactes |

Les anomalies de `references_mitre` portent une portée préfixée —
`references_mitre:T0846` — pour ne jamais s'afficher sur une fiche THQ
homonyme. `--strict` rend les rejets bloquants, comme pour les fiches :

```
uv run mcp_mitre.py --test --strict
→ Interne     3 fiche(s) (1 valide(s), 2 brouillon(s)), next_id THQ0004
              0 ecartee(s), 5 avertissement(s), 1 sans ancrage ATT&CK, ...
              6 technique(s) MITRE avec references internes
              (3 entree(s) ecartee(s)), 10 reference(s) CTI indexee(s)
  ECHEC : T0846 : entree dupliquee dans 'references_mitre' - regrouper ses
          references dans une seule entree | ...
```

`--test` vérifie aussi la réciprocité du nouvel index : chaque entrée indexée
existe, chaque entrée ancrée sur une technique vivante est retrouvée par
`get_technique`, et l'index des rapports compte exactement les références
chargées.

## 8. Ce que les réponses gagnent

Des champs additifs, une note qui change (§3). Rien n'est retiré.

| Champ | Où | Quand |
|---|---|---|
| `references_internes` | `get_technique`, `search_techniques` | Un rapport interne est rattaché, en dernière position |
| `rapports`, `rapport_count` | `search_internal` | Toujours |
| `mitre_candidats`, `homonymes` | `search_internal` | Base MITRE disponible |
| `proposition` | `search_internal` | Toujours |
| `references` | fiche THQ | Toujours, liste validée |
| `references_mitre`, `references_mitre_count` | `list_internal_techniques` | Toujours |
| `references_mitre`, `references_mitre_ecartees`, `rapports` | `compteurs` | Toujours |
| `type_entree`, `entrees`, `references_internes` | `get_internal_technique` | Identifiant ATT&CK demandé |

Les descriptions de `list_internal_techniques`, `get_internal_technique` et
`search_internal` sont enrichies ; `search_internal` gagne le paramètre
optionnel `matrix`, validé comme partout : une valeur inconnue lève une erreur
explicite, `ICS`, `OT`, `SCADA` et `IT` sont acceptés.

## 9. Lancement par `uv run`

Le fichier porte désormais ses **métadonnées de script PEP 723** en tête :

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
```

Toutes les commandes deviennent `uv run mcp_mitre.py …` : `--test`, `--http`,
`--doc`, l'aide `--help` et la configuration du client MCP. `uv` réutilise un
interpréteur compatible déjà présent, ou en télécharge un au premier
lancement. Sous Linux et macOS, le shebang rend le fichier exécutable
directement : `./mcp_mitre.py --test`.

```json
"mitre-attack": {"command": "uv", "args": ["run", "C:/chemin/vers/mcp_mitre.py"]}
```

**Le plancher est Python 3.10.** Le serveur passe `--test` de 3.8 à 3.13, mais
3.8 et 3.9 ne sont plus maintenues ; les déclarer aurait laissé `uv` retenir
un interpréteur sans correctif de sécurité pour un serveur qui écoute en
HTTP.

**Le choix de l'interpréteur ne change pas le mapping.** C'était la question
à trancher : `uv` peut retenir une autre version de Python que la commande
`python` utilisée pour une évaluation antérieure. Mesuré sur 2 570 appels —
chaque technique par son identifiant, son nom et sa description, plus les
requêtes des échantillons Modbus —, les réponses sont **identiques à l'octet**
sous 3.10, 3.11, 3.12 et 3.13.

## 10. Ce qui ne change pas

Vérifié explicitement plutôt qu'affirmé :

- les **18 outils** et les **16 alias**, avec leurs paramètres — un seul
  paramètre optionnel ajouté ;
- les réponses des **douze outils ATT&CK**, à l'octet, sans rapport rattaché ;
- les **descriptions** des douze outils ATT&CK dans `tools/list` ;
- les **révocations en chaîne** : 158 redirections, 0 sans remplaçant vivant ;
- le serveur **n'écrit jamais** : aucun outil d'écriture, le fichier s'édite
  à la main puis `internal_reload` ;
- la **marque haute** des identifiants THQ et `meta.dernier_id_attribue` ;
- un référentiel v2.2.1 se charge **à l'identique** ;
- le mode **`--http`** : `/healthz` rend `"version": "2.2.2"`, les outils
  internes répondent comme en stdio ;
- `--test` sort en **0 anomalie de réciprocité, 0 référence orpheline**.

Un coût, un seul : `search_internal` interroge désormais MITRE une fois par
appel. Sa latence médiane passe d'environ 0,04 ms à environ 5 ms sur le banc
de mesure. `search_techniques` est inchangée, dans le bruit de mesure.

## 11. Migration depuis la v2.2.1

**Installez `uv`, remplacez le fichier.** Aucun format de cache modifié.

Dans la configuration du client MCP, `"command": "python"` devient
`"command": "uv"`, et `"args"` commence par `"run"`. Dans les scripts et les
tâches planifiées, `python mcp_mitre.py` devient `uv run mcp_mitre.py`.

Le référentiel v2.2.1 se recharge à l'identique ;
ajoutez `"references_mitre": []` pour commencer à rattacher des rapports.

Trois points à vérifier côté client.

**Si vos fiches THQ portaient déjà un champ libre `references`**, il est
désormais validé : chaque élément doit être un objet `{titre, lien}`. Les
éléments non conformes sont écartés avec un avertissement, la fiche reste.

**Si vous exploitez la `note` de `search_internal`**, elle ne propose plus de
nouvelle fiche quand MITRE couvre le comportement. Lisez plutôt
`proposition.type`, stable et fait pour être consommé.

**Si vous comptez `compteurs.fiches_ecartees`**, les rejets de
`references_mitre` n'y figurent pas : ils ont leur compteur,
`references_mitre_ecartees`. Sur un référentiel v2.2.1, les valeurs sont
inchangées.

**Une évaluation de mapping faite en v2.2.1 reste valable**, sous une seule
condition : le même cache ATT&CK.

Le numéro de version est rendu par `mitre_stats`, par la sonde `/healthz` du
mode `--http` et par la bannière de `--test` :

```
uv run mcp_mitre.py --test
→ Serveur : mcp-mitre-attack v2.2.2
  ...
  Interne     0 fiche(s) (0 valide(s), 0 brouillon(s)), next_id THQ0001
              0 ecartee(s), 0 avertissement(s), 0 sans ancrage ATT&CK, ...
              0 technique(s) MITRE avec references internes
              (0 entree(s) ecartee(s)), 0 reference(s) CTI indexee(s)
  OK
```
