# Release Notes — Serveur MCP MITRE ATT&CK v2.2.1 « calibration du score et départage des matrices »

## Vue d'ensemble

La v2.2.1 est une **version corrective**. Elle n'ajoute aucun outil, ne modifie
aucune signature, ne retire aucun garde-fou. Les **dix-huit outils** et les
**seize alias** de la v2.2 sont tous là, avec leurs paramètres. Elle corrige
sept défauts du moteur de mapping, dont deux que les notes de la v2.2
annonçaient comme des acquis.

Ces deux-là méritent d'être dits d'emblée, parce qu'ils contredisent ce qui a
été publié.

La v2.2 décrivait son départage à score égal comme « déterministe et
explicité », en terminant par l'identifiant. Il l'était — et c'est exactement ce
qui produisait le défaut : tout identifiant ICS commençant par `T0`, il passait
devant n'importe quel `T1xxx` en ordre lexical. Sur les vingt-six noms de
techniques que les deux matrices portent à l'identique, **vingt-cinq
renvoyaient la version industrielle en tête**, à score 1.0 et sans aucun
signal.

La v2.2 annonçait aussi que `search_internal` suivait « exactement le même
chemin de code » que `search_techniques`. La fonction de score, oui — un seul
exemplaire, toujours. Mais la tokenisation, non : la recherche MITRE étendait
le jargon d'analyste côté requête, la recherche interne ne l'étendait pas. La
promesse « mêmes règles » était vraie de la formule, fausse des entrées.

Deux sémantiques publiées changent **volontairement** : le score n'est plus une
couverture pure de la requête, il est plafonné dans deux cas où la couverture
atteignait 1.0 sans rien prouver (§3 et §4) ; et le départage intercale la
matrice avant l'identifiant (§2). Trois champs **additifs** apparaissent dans
les réponses — `homonymes`, `matched.name_exact`, `matched.pivot` — et quatre
notes nouvelles. Aucune réponse ne perd de champ.

Tous les chiffres ci-dessous sont **mesurés** sur le serveur livré, chargé avec
ATT&CK 19.2 (Enterprise + ICS, 794 techniques, 692 libellés de sources, 158
redirections).

---

## 1. Les mots vides pesaient dans le score

La v2.1 exigeait trois caractères pour retenir un token alphabétique. La v2.2
est descendue à deux, et aucun mot anglais de deux lettres ne figure dans la
liste d'arrêt. Résultat, cent dix-neuf tokens de deux lettres sont entrés dans
l'index :

```
to : 790 techniques sur 794      in : 649      by : 495
of : 704                          on : 533      is : 431
or : 662                          an : 505      be : 658      as : 650
```

Dix tokens couvrent plus de la moitié du corpus. Le score étant une couverture
de la requête, ces mots gonflaient le dénominateur sans rien discriminer :

```
« exfiltration of data to an external server »
  tokens = [an, data, exfiltr, extern, of, server, to]
  trois parasites sur sept, soit 43 % du denominateur
```

Les bons candidats perdaient de 0,06 à 0,09, ce qui les faisait passer sous le
seuil « fort » de 0,6 :

```
                                                  v2.2     v2.2.1
« use of wmi to execute a command »        T1047   0.706 →  0.784
« clear the event log on a windows host »  T1685.005 0.779 → 0.843
« process injection in to a remote process » T1055.001 0.676 → 0.760
« an unauthorized command message to a plc » T1692.001 0.601 → 0.586 → 0.469 *
```

Le pire cas n'était pas une perte de score, c'était un gain imméritté. Une
requête de pure grammaire produisait un candidat fort, **sans la moindre
réserve** :

```
search_techniques("on or of")
  v2.2   → T1612, score 0.601, total_matches 793, aucune note
  v2.2.1 → 0 resultat, note: "aucun terme significatif dans la requete"
```

Retour au minimum de trois caractères, deux seulement pour les tokens porteurs
d'un chiffre — `c2`, `2fa`, `t1003`, `sha256` restent indexés.

*\* le troisième chiffre reflète aussi le plafond du §3 : la requête ne compte
que quatre termes significatifs après correction.*

## 2. Vingt-cinq homonymes sur vingt-six renvoyaient la matrice industrielle

Vingt-six noms de techniques existent à l'identique dans Enterprise et dans
ICS. À score égal — et il l'est toujours, puisque le nom est le même — le
départage descendait jusqu'à l'identifiant. Tout identifiant ICS commence par
`T0`, tout identifiant Enterprise par `T1` : l'ordre lexical tranchait
systématiquement en faveur de l'industriel.

```
search_techniques("valid accounts")
  v2.2   → T0859 [ICS]        1.0   puis T1078 [Enterprise] 1.0
  v2.2.1 → T1078 [Enterprise] 1.0   puis T0859 [ICS]        1.0

  meme cause : network sniffing, screen capture, masquerading, rootkit,
  service stop, user execution, native api, supply chain compromise...
```

Le biais était déterministe, pas aléatoire — donc reproductible sur les vingt-
six noms, dont vingt-cinq basculaient du mauvais côté.

Deux corrections. Le **rang de matrice s'intercale avant l'identifiant**,
Enterprise en premier. Sous filtre `matrix=`, ce critère est neutre : une seule
matrice est en lice. Sans filtre, le contexte informatique redevient le défaut.

Et surtout, l'ambiguïté cesse d'être subie : un champ **`homonymes`** la nomme,
avec une note qui dit quoi faire.

```
search_techniques("valid accounts")
→ "homonymes": [{"name": "Valid Accounts",
                 "techniques": [{"id": "T1078", "matrix": "Enterprise"},
                                {"id": "T0859", "matrix": "ICS"}]}],
  "note": "1 nom(s) present(s) dans LES DEUX matrices (voir `homonymes`) :
           preciser matrix='Enterprise' pour un contexte IT,
           matrix='ICS' pour un contexte industriel"
```

Ce champ n'apparaît que lorsque les résultats renvoyés contiennent
effectivement des techniques homonymes de matrices différentes, et jamais sous
filtre `matrix=`.

**Le serveur ne connaît pas la matrice attendue par l'appelant.** Il ne connaît
que le paramètre `matrix` qu'on lui transmet. Mesuré sur douze comportements
typés : trois premiers résultats sur douze dans la mauvaise matrice sans le
paramètre, **zéro avec**. Le champ `homonymes` amortit ; il ne remplace pas le
filtre.

## 3. Un seul mot ne peut plus valoir un mapping

Le score mesure la couverture de la requête. Avec un seul mot significatif,
cette couverture atteint 1.0 dès que le mot figure dans un nom — mécaniquement,
sans rien prouver.

```
search_techniques("windows")
  v2.2   → T1564.003 1.0 | T1543.003 1.0 | T1222.001 1.0
  v2.2.1 → T1564.003 0.59 | T1543.003 0.59 | T1222.001 0.59
           note: "requete d'un seul terme : score plafonne a 0.59, aucun
                  candidat ne peut etre declare fort - reformuler en un
                  comportement atomique (ex 'lsass credential dumping')"

  meme effet sur : data, file, service, network
```

Le plafond est fixé à 0,59, juste sous le seuil « fort », et il ne s'applique
ni à un **identifiant explicite** — `T1003.001` reste à 1.0, il est vérifiable
— ni à un **nom strictement égal à la requête** : `masquerading` rend bien
T1036 à 1.0.

C'est un changement assumé de la sémantique publiée en v2.2. Le score reste une
couverture ; il cesse d'être *seulement* une couverture.

## 4. Un nom de groupe n'est pas un mapping

Depuis la v2.2, les noms et alias des groupes, software et campagnes favorisent
les techniques qu'ils utilisent. C'est utile quand la requête décrit aussi un
comportement. Réduite au seul nom de l'entité, elle produisait un aplatissement
complet :

```
search_techniques("apt29")
  v2.2   → 66 correspondances, dont 40 a EXACTEMENT 0.9
           40 « candidats forts » indiscernables, departages par la seule
           longueur de leur nom
  v2.2.1 → les memes, a 0.45, aucun declare fort
           matched: {"groups": ["G0016 APT29"],
                     "pivot": "entite seule : piste, pas un mapping"}
           note: "aucune correspondance lexicale : ces techniques sont
                  seulement celles utilisees par G0016 APT29 - liste faisant
                  foi via get_group / get_software / get_campaign, pas un
                  mapping du comportement decrit"

  cobalt strike : 74 correspondances | emotet : 47 | mimikatz : 17
```

Une technique dont la **seule** preuve est « une entité nommée dans la requête
l'utilise » est plafonnée à 0,45 et marquée `matched.pivot`. Le bonus d'entité
reste entier dès qu'une preuve lexicale l'accompagne :

```
search_techniques("apt29 credential dumping")  → T1003.004 0.9  (inchange)
search_techniques("mimikatz lsass memory")     → T1003.001 1.0  (inchange)
```

## 5. Toute technique reste trouvable par son nom

Conséquence directe du §1 : T1053.002 s'appelle « At ». Deux caractères, aucun
token significatif — la technique devenait introuvable par son propre nom.

Plutôt que d'assouplir le filtre et de réintroduire le défaut, un **index des
noms exacts** est construit au chargement, indépendant de la tokenisation. Il
couvre le nom court et le nom complet `Parente: Sous-technique`.

```
search_techniques("At", matrix="Enterprise")
  v2.2.1 → T1053.002 « At » 1.0

search_techniques("OS Credential Dumping: LSASS Memory")
  v2.2.1 → T1003.001 1.0
```

Mesure sur les 794 techniques interrogées par leur propre nom : **zéro
introuvable** dans le top-5, et le rang 1 passe de 93,3 % à **96,6 %**.

## 6. Un message multi-lignes ne reste plus sans réponse

L'assemblage des messages stdio multi-lignes comparait le nombre d'accolades
ouvrantes et fermantes sans tenir compte des chaînes. Un message pretty-printé
dont une valeur contenait `}` — une description d'incident, un extrait de log —
était déclaré complet trop tôt, rejeté, et **la requête restait sans réponse
pour son identifiant** : le serveur émettait deux `Parse error` avec `id: null`
et le client attendait dans le vide. Le même message sur une seule ligne
passait.

```
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": { "name": "search_techniques",
              "arguments": { "query": "closing brace } inside" }}}

  v2.2   → id=null ERREUR, id=null ERREUR
  v2.2.1 → id=7 ok
```

Les accolades sont désormais comptées hors chaînes, guillemets échappés
compris. Un JSON multi-lignes réellement invalide est toujours rejeté, et le
plafond de tampon d'un mégaoctet est inchangé.

## 7. Deux correctifs du référentiel interne

**`list_internal_techniques` prenait deux instantanés.** Elle listait
`internal.fiches.values()`, puis ré-interrogeait `internal.fiches` par
identifiant. En mode `--http`, multi-thread, un `internal_reload` concurrent
remplaçait le dictionnaire entre les deux et la seconde lecture rendait `None`,
non filtré. Mesuré avec dix lecteurs et deux rechargeurs : **92 réponses sur
601 923** annonçaient `result_count: 12` avec une liste de douze `null`. Un
instantané unique sert désormais toute la réponse : zéro incohérence sur
629 582 appels après correction.

**`search_internal` n'étendait pas le jargon.** La recherche MITRE appelle la
tokenisation avec l'expansion des synonymes, la recherche interne l'appelait
sans. Le même énoncé franchissait le seuil fort d'un côté et restait sous le
seuil de l'autre :

```
                        MITRE      interne v2.2    interne v2.2.1
« exfil cloud »          1.0          0.5              1.0
« creds memoire »        0.5          0.175            0.35
« privesc »              1.0          aucun resultat   trouve
```

Conséquence pratique : l'anti-doublon se déclenchait à tort — « aucune fiche
interne similaire : une nouvelle fiche peut être proposée » — et invitait à
créer un doublon. Un mot corrigé, la promesse de la v2.1 redevient vraie.

## 8. Ce que les réponses gagnent

Trois champs additifs et quatre notes. Rien n'est retiré.

| Champ | Où | Quand |
|---|---|---|
| `homonymes` | `search_techniques` | Un nom des résultats existe dans les deux matrices, sans filtre `matrix` |
| `matched.name_exact` | résultat | Le nom de la technique est strictement égal à la requête |
| `matched.pivot` | résultat | Seule preuve : une entité de la requête utilise cette technique |

Les quatre notes nouvelles : ambiguïté de matrice (§2), requête d'un seul terme
(§3), résultats de pivot seuls (§4), et un rappel quand le candidat de tête est
une **sous-technique dont la parente est elle aussi candidate** — la description
de l'outil prescrit le niveau parent par défaut, la note le redit là où le
classement ne le montre pas.

La description de `search_techniques`, que le modèle lit dans `tools/list`,
gagne deux points de méthode : préciser `matrix` puisque vingt-six noms sont
partagés, et ne pas conclure sur une requête d'un seul terme ou réduite à un
nom d'entité.

## 9. Ce que ça donne, mesuré

Banc de 46 comportements SOC, vérité de terrain résolue à travers les
redirections d'ATT&CK 19.2 :

| | v2.2 | v2.2.1 |
|---|---|---|
| Top-1 | 37/46 | **38/46** |
| Top-3 | 46/46 | 46/46 |
| Candidats de tête ≥ 0,6 | 29/46 | **31/46** |
| Homonymes renvoyant l'ICS en tête | 25/26 | **1/26** |
| Technique introuvable par son nom | 1/794 | **0/794** |
| Rang 1 par nom propre | 93,3 % | **96,6 %** |
| « on or of » | T1612 à 0,601 | 0 résultat + note |
| « windows », « data », « service » | trois à 1,0 | 0,59 + note |
| « apt29 » | 40/40 forts à 0,9 | 0/40, tous à 0,45 |

Le classement change peu — le moteur trouvait déjà la bonne technique. Ce qui
change, c'est **la confiance qu'on peut accorder au score** : deux requêtes
supplémentaires franchissent honnêtement le seuil fort, et trois familles de
requêtes cessent de le franchir malhonnêtement.

## 10. Ce qui ne change pas

Vérifié explicitement plutôt qu'affirmé :

- les **18 outils** et les **16 alias** de la v2.2, avec leurs paramètres ;
- `windows services` renvoie toujours **T1543.003 en tête à 1.0** ;
- les **révocations en chaîne** restent transitives : 158 redirections, 0 sans
  remplaçant vivant ; `T1086` redirige vers `T1059.001` ;
- l'**index des sources** conserve ses libellés composites : 692 libellés,
  `EventCode` rend 58 sources, `auditd:SYSCALL` en rend 32 ;
- `get_datasources("Windows", matrix="ICS")` rend toujours **3 libellés pour 4
  techniques**, et les chiffres sans filtre sont inchangés ;
- une **matrice inconnue lève une erreur explicite**, `SCADA`, `OT` et `IT`
  restent acceptés comme alias ;
- `mitre_update` **ne remplace la base qu'en cas de succès complet** : après un
  échec réseau simulé, les 794 techniques sont toujours là ;
- `get_tactics` respecte l'**ordre officiel de la kill chain** ;
- le **cloisonnement des matrices** tient : zéro technique rattachée à la
  tactique d'une autre matrice ;
- `--test` sort en **0 anomalie de réciprocité, 0 référence orpheline** ;
  `--strict` sort toujours en code 1 sur un référentiel fautif ;
- performance inchangée : **3,7 ms** médian sur `search_techniques`, 40
  requêtes HTTP parallèles servies en 0,44 s.

## 11. Migration depuis la v2.2

**Remplacez le fichier, c'est tout.** Aucune configuration à changer, aucun
format de cache modifié, aucune migration de données. Le référentiel interne se
recharge à l'identique.

Trois points à vérifier côté client.

**Si vous seuilez sur 0,6**, attendez-vous à voir disparaître les candidats
forts issus de requêtes d'un seul mot ou d'un seul nom d'entité. C'est l'effet
recherché, mais un pipeline qui comptait dessus le sentira.

**Si vous ne passez pas `matrix`**, vos premiers résultats vont changer sur les
vingt-six noms partagés : Enterprise passe devant. Si votre contexte est
industriel, passez `matrix="ICS"` — le filtre est souverain et l'a toujours
été.

**Si vous exploitez `matched`**, deux clés nouvelles peuvent apparaître,
`name_exact` et `pivot`. Un consommateur qui itère sur les clés sans les
connaître doit les tolérer.

Le numéro de version est rendu par `mitre_stats`, par la sonde `/healthz` du
mode `--http` et par la bannière de `--test` :

```
python mcp_mitre.py --test
→ Serveur : mcp-mitre-attack v2.2.1
  ...
  Integrite   0 anomalie(s) de reciprocite, 0 reference(s) orpheline(s)
  OK
```
