# Notes de version — Serveur MCP MITRE ATT&CK v2.0

## Vue d'ensemble

La v2.0 est une **refonte complète du moteur** de la v1.1.

Le squelette ne change pas : transport stdio en JSON-RPC, bibliothèque standard
Python uniquement, journal d'audit JSONL, base hybride Enterprise (IT) + ICS
(OT) cloisonnée par matrice. Ce qui est réécrit, c'est le cœur : la lecture du
catalogue MITRE, le moteur de recherche, et la façon dont les résultats sont
présentés au modèle de langage.

C'est une version **majeure** parce que le format des réponses change et que
les outils sont renommés. Aucune rupture n'est silencieuse : toutes sont
listées en fin de document, et les anciens noms d'outils restent acceptés.

Tous les chiffres cités sont **mesurés** sur les deux serveurs, chargés avec le
même catalogue MITRE (release 19.2, Enterprise + ICS, 794 techniques), sauf là
où l'on compare explicitement deux releases différentes.

**Plan du document**

- Rappel : de quoi parle ce serveur
- Partie I — Ce que le serveur lit dans le catalogue MITRE (2 chapitres)
- Partie II — La méthode de mapping encodée dans le serveur (8 chapitres)
- Partie III — Surface d'outils
- Partie IV — Défauts internes corrigés
- Partie V — Garde-fous conservés et renforcés
- Partie VI — Économie de contexte
- Partie VII — Vérification
- Changements de contrat, compatibilité, limites connues

---

## Rappel : de quoi parle ce serveur

Pour que la suite soit lisible sans connaître MITRE, voici le minimum.

MITRE ATT&CK est un catalogue public de comportements d'attaquants,
téléchargeable sous forme de fichiers de données. Il contient :

| Objet | Identifiant | Exemple réel |
|---|---|---|
| **Technique** | `T1003` | « OS Credential Dumping » — voler les mots de passe en mémoire |
| **Sous-technique** | `T1003.001` | « LSASS Memory » — la même chose, via le processus LSASS de Windows |
| **Tactique** | `TA0006` | « Credential Access » — l'objectif poursuivi |
| **Groupe** | `G0034` | « Sandworm Team » — un groupe d'attaquants identifié |
| **Software** | `S0002` | « Mimikatz » — un outil utilisé par des attaquants |
| **Mitigation** | `M1043` | « Credential Access Protection » — une contre-mesure |

MITRE publie deux catalogues séparés : **Enterprise** pour l'informatique
classique (techniques numérotées `T1***`) et **ICS** pour les systèmes
industriels (techniques numérotées `T0***`). Ce serveur charge les deux.

Le serveur fait trois choses : télécharger les fichiers et les mettre en cache,
les analyser pour construire une base en mémoire, et exposer des outils qu'un
modèle de langage appelle.

**Le but final s'appelle le mapping TTP** : à partir d'un signal brut — une
ligne de journal, une alerte, un paragraphe de rapport — retrouver les
identifiants ATT&CK qui décrivent le comportement observé. C'est un travail de
rattachement, et il n'a de valeur que s'il est exact : un identifiant faux est
pire qu'une absence de réponse, parce qu'il se propage ensuite dans les
rapports, les tableaux de bord et les décisions.

---

# Partie I — Ce que le serveur lit dans le catalogue MITRE

## 1. Lecture des deux modèles de détection MITRE

### Ce qu'est le « modèle de détection »

Quand MITRE décrit une technique d'attaque, il indique aussi **comment la
repérer dans les journaux d'événements** des machines. Depuis la release 18, il
le fait avec trois niveaux d'objets emboîtés.

**Niveau 1 — la stratégie de détection.** Une phrase qui dit quoi surveiller :
> « Détection du vol d'identifiants depuis la mémoire de LSASS »

**Niveau 2 — l'analytic.** La règle concrète rattachée à cette stratégie. MITRE
en publie 1758 pour Enterprise dans la release 19.2.

**Niveau 3 — la source de logs.** Chaque analytic indique dans quel journal
aller regarder, sous la forme de deux champs :

```json
{ "name": "auditd:SYSCALL", "channel": "socket/connect" }
```

- **`name`** désigne le journal à consulter. Ici le journal d'audit Linux.
  Autres exemples réels : `WinEventLog:Sysmon`, `WinEventLog:Security`,
  `AWS:CloudTrail`.
- **`channel`** précise *quelle partie* de ce journal. Ici, les appels système
  de type connexion réseau.

Les deux mis bout à bout donnent : « dans le journal auditd, regarde les
événements SYSCALL de type socket/connect ».

### Le problème : la v1.1 ne sait lire que ce modèle-là

MITRE a changé de modèle entre ses releases 17.1 et 18.0. Mesuré sur les
fichiers eux-mêmes :

| Release | Anciens champs `x_mitre_data_sources` / `x_mitre_detection` | Stratégies | Analytics |
|---|---|---|---|
| **17.1** | 639 et 726 techniques | 0 | 0 |
| **18.0** | 0 et 0 | 691 | 1739 |
| 19.2 | 0 et 0 | 699 | 1758 |

La bascule est totale : les anciens champs disparaissent d'un coup, le nouveau
modèle apparaît d'un coup.

La v1.1 ne lit que le nouveau modèle. Elle n'exploite ni
`x_mitre_data_sources`, ni `x_mitre_detection`, ni la relation `detects`
publiée par les composants de données. **Sur un catalogue en 17.1 ou
antérieur, tout son pipeline de détection est donc vide**, alors que
l'information est présente dans 639 techniques. Mesuré :

```
v1.1, catalogue 17.1
  Enterprise   14 tactiques, 679 techniques,   0 avec détection
  ICS          12 tactiques,  83 techniques,   0 avec détection
                             0 sources de données

  mitre_technique("T1003.001") → "detection": "", "data_sources": []
  mitre_datasources("Process Creation") → 0 technique
```

C'est une panne complète, et elle est **silencieuse** : le serveur démarre,
répond, et `--test` imprime `OK`. Le modèle demande « avec quels journaux
détecter cette attaque » et reçoit une liste vide, sans savoir que c'est un
défaut de lecture et non une absence d'information chez MITRE.

Le cas n'est pas théorique. Il se produit dès qu'un fichier de cache antérieur
à la bascule reste sur le disque, ou qu'on charge délibérément une release
ancienne pour reproduire une étude.

### La correction

Le serveur lit **les deux modèles** et indique lequel il a trouvé.

```
v2.0, catalogue 19.2
  Enterprise   15 tactiques, 697 techniques, 697 avec stratégie, 652 avec source  (modèle: strategies)
  ICS          12 tactiques,  97 techniques,  97 avec stratégie,  85 avec source  (modèle: strategies)

v2.0, catalogue 17.1
  Enterprise   14 tactiques, 679 techniques,   0 avec stratégie, 639 avec source  (modèle: hérité)
  ICS          12 tactiques,  83 techniques,   0 avec stratégie,  71 avec source  (modèle: hérité)

  get_technique("T1003.001") sur 17.1
  → "data_sources": ["Command Execution","File Creation","Logon Session Creation",
                     "OS API Execution","Process Access", ...]
    "legacy_detection": 1119 caractères de texte de détection
  get_datasources("Process Creation") sur 17.1 → 281 techniques
```

Le champ `detection_model` de `mitre_stats` vaut `strategies`, `hérité` ou
`absent` selon ce qui a été trouvé. `--test` sort en **code 1** si la
couverture de détection d'une matrice tombe sous 25 % : la panne décrite plus
haut ne peut plus passer inaperçue.

---

## 2. Assainissement des libellés de sources de logs

### Le problème : le champ `channel` contient parfois de la prose

MITRE ne remplit pas toujours `channel` avec un nom court. Souvent il y met la
logique de détection complète, en texte libre. Exemple réel extrait du fichier :

```json
{
  "name":    "ALB:HTTPLogs",
  "channel": "AWS ALB/ELB/GCP/Azure Application Gateway HTTP logs with unusual
              methods, long URIs, serialized payloads, 4xx/5xx bursts"
}
```

Mesuré sur la release 19.2 d'Enterprise : **4182 champs `channel`, dont 863
font plus de 60 caractères**, le plus long en fait 225. Sur les 2382 valeurs
distinctes, seules 284 n'ont aucun espace.

La v1.1 colle systématiquement les deux bout à bout pour fabriquer une
étiquette d'index, `name:channel`. Résultat, sa liste d'étiquettes contient :

```
auditd:SYSCALL:socket/connect                                   ← correct et utile
ALB:HTTPLogs:AWS ALB/ELB/GCP/Azure Application Gateway HTTP
logs with unusual methods, long URIs, serialized payloads...    ← inutilisable
```

C'est pour cela que la v1.1 annonce **2796 « sources de données »** : ce ne
sont pas 2400 sources de plus qu'ailleurs, ce sont 2400 étiquettes déformées.
Mesuré : **1325 de ces 2796 étiquettes dépassent 60 caractères**, longueur
moyenne 59,6. Concrètement :

```
v1.1  mitre_datasources("auditd")
→ 364 « libellés » correspondants, affichés au modèle sous forme de phrases
```

### La correction

Un `channel` n'est retenu pour composer une étiquette que s'il **ressemble à un
canal** : pas d'espace, 40 caractères au maximum. Sinon seul le `name` est
gardé. Les valeurs vides et les littéraux `None`, `N/A`, `-` sont filtrés, côté
Enterprise comme côté ICS.

```
v2.0  index : 692 étiquettes (415 noms et composants + 277 composites propres)
      étiquette la plus longue : 78 caractères
      exemples : "Process Creation", "auditd:SYSCALL", "AWS:CloudTrail:AssumeRole"

v2.0  get_datasources("auditd")            → 50 libellés, 351 techniques
v2.0  get_datasources("Process Creation")  →  1 libellé, 476 techniques
v2.0  get_datasources("4688")              →  1 libellé, 106 techniques
```

L'information utile (`auditd:SYSCALL:socket/connect`) est conservée, la prose
est écartée.

Sur les anciens catalogues, les libellés hérités sont normalisés au passage :
MITRE y écrivait `Command: Command Execution`, on ne garde que
`Command Execution`, ce qui évite d'indexer deux fois la même source. L'index
17.1 passe ainsi de 222 à 111 étiquettes réellement distinctes.

---

# Partie II — La méthode de mapping encodée dans le serveur

Les huit points qui suivent ne sont pas des recommandations d'usage écrites à
côté du serveur : ils sont **inscrits dans le comportement du serveur
lui-même**, dans les descriptions d'outils que le modèle lit avant d'appeler,
et dans les champs que les réponses contiennent. Chacun est développé
ci-dessous avec le problème qu'il traite, le mécanisme retenu, et des mesures.

---

## Préalable indispensable : « lexicale, pas sémantique »

C'est la phrase la plus importante du document, et la plus facile à mal lire.
**La recherche n'est pas devenue sémantique. Elle ne l'est pas et ne le
prétend pas.**

Il y a trois niveaux possibles pour une recherche textuelle. Le serveur est
passé du premier au deuxième, pas au troisième.

**Niveau 1 — la comparaison de fragments de lettres.** C'est ce que faisait la
v1.1. Elle vérifiait si la suite de lettres de la requête se trouvait quelque
part dans le texte, sans se soucier des frontières de mots. Chercher `port`
retenait donc `Trans`**`port`**` Agent`, `Security Sup`**`port`**` Provider` et
`**Port**able Executable Injection`, parce que les quatre lettres p-o-r-t y
sont effectivement présentes.

**Niveau 2 — la comparaison de mots entiers.** C'est ce que fait la v2.0. Le
texte est découpé en mots au chargement, et la comparaison porte sur des mots,
pas sur des suites de lettres. `port` ne trouve plus `support`, parce que
`support` est un mot différent de `port`. Une correction de terminaison est
appliquée des deux côtés — de la requête et du catalogue — pour que
`dumping` et `dump`, ou `services` et `service`, soient reconnus comme le même
mot. C'est tout. Le serveur ne comprend toujours pas ce que les mots veulent
dire.

**Niveau 3 — la compréhension du sens.** Ce serait savoir que « vol de mots de
passe » et « credential dumping » désignent la même chose, ou que « tâche
planifiée » traduit « scheduled task ». **Le serveur ne fait pas cela.** Il
faudrait pour cela un modèle de langage embarqué ou une base vectorielle, donc
des dépendances externes, un temps de chargement et une consommation mémoire
que ce projet a choisi de ne pas prendre.

### Démonstration mesurée

Le même comportement — voler les identifiants stockés en mémoire — formulé de
quatre façons :

| Requête | Résultat |
|---|---|
| `vol d'identifiants dans la memoire` (français) | **0 candidat** |
| `extraction des mots de passe Windows` (français) | 225 candidats, meilleur score **0,27** — du bruit |
| `password theft from memory` (anglais, mais pas le vocabulaire ATT&CK) | T1003.001 à **0,45**, sous le seuil de candidat fort |
| `stealing passwords` (anglais courant) | **T1649 Steal or Forge Authentication Certificates à 0,675** — la mauvaise réponse en tête |
| `credential dumping` (vocabulaire ATT&CK) | **T1003 OS Credential Dumping à 1,0** |

La quatrième ligne est la plus instructive : la requête en anglais courant ne
renvoie pas rien, elle renvoie **une réponse fausse avec un score élevé**,
parce que les mots « steal » et « password » apparaissent bel et bien dans le
nom d'une autre technique. Une recherche lexicale ne peut pas faire la
différence. C'est exactement pour cette raison que les points 2 et 3 qui
suivent — les preuves et la vérification obligatoire — existent.

---

## Point 1 — Une requête = un comportement atomique, en mots-clés anglais ATT&CK

### Ce que le point signifie

Une requête doit décrire **un seul comportement**, formulé avec les mots
qu'emploie MITRE, en anglais. Pas une phrase, pas un récit, pas plusieurs
étapes d'une attaque à la fois, pas du français.

### Pourquoi le serveur y tient

Le score mesure la **couverture de la requête** : chaque mot significatif de la
requête compte une fois, et le score final est la proportion de ces mots
retrouvés. C'est un choix délibéré, qui évite qu'une technique à longue
description remonte simplement parce qu'elle contient beaucoup de mots. Mais il
a une conséquence directe : **plus la requête contient de mots, plus chaque mot
retrouvé pèse peu**, et plus le score de la bonne réponse baisse
mécaniquement.

### Mesures

**Une phrase complète contre une requête atomique**, pour le même signal :

```
"the attacker dumped credentials from lsass memory using mimikatz"
→ T1003.001  LSASS Memory          0.61
  T1003      OS Credential Dumping 0.47   ← la technique parente reléguée au 2e rang

"lsass credential dumping"
→ T1003      OS Credential Dumping 0.667  ← la parente reprend sa place
  T1003.001  LSASS Memory          0.567
```

La phrase contient des mots — `attacker`, `using`, `from` — qui ne discriminent
rien et qui diluent le score. Le serveur en écarte une partie, mais il ne peut
pas deviner que `mimikatz` est un outil et non le comportement recherché.

**Trois comportements à la fois contre un seul** :

```
"phishing attachment powershell execution registry run key persistence"
→ T1547.001  Registry Run Keys / Startup Folder   0.419   ← sous le seuil de 0,6
  T1546.012  Image File Execution Options         0.3
  (ni le hameçonnage ni PowerShell ne remontent)

"registry run key"     → T1547.001  Registry Run Keys / Startup Folder   1.0
"powershell execution" → T1059.001  PowerShell                           0.675
```

La requête composite ne trouve **aucun** de ses trois comportements
correctement : le meilleur candidat passe sous le seuil de candidat fort, et
deux comportements sur trois disparaissent. Séparées, les mêmes recherches
donnent chacune le bon résultat.

**Le français** :

```
"vol d'identifiants dans la memoire"  → 0 candidat
"tache planifiee"                     → 0 candidat
```

Le serveur ne renvoie pas un mauvais résultat : il renvoie l'absence de
résultat, avec la note explicite du point 5. C'est le comportement voulu.

### Comment c'est encodé dans le serveur

La règle est le premier alinéa de la description de l'outil
`search_techniques`, que le modèle lit avant chaque appel : *« UNE requête = UN
comportement atomique, en mots-clés ANGLAIS ATT&CK (ex 'lsass credential
dumping') »*. Le champ `query_tokens` de chaque réponse montre au modèle les
mots réellement retenus, ce qui lui permet de constater lui-même qu'une requête
de dix mots n'en a gardé que six.

---

## Point 2 — Score normalisé [0..1] et preuves de correspondance

### Le problème de la v1.1

Le score de la v1.1 est un entier de recouvrement sans échelle. Rien dans la
réponse ne permet de savoir si un score est bon.

```
v1.1  mitre_search("lsass credential dumping")
→ T1003 : 8   |   T1003.001 : 5   |   T1552.001 : 5      (8 sur quoi ?)
```

Un entier sans borne supérieure est ininterprétable : le modèle ne peut ni
comparer deux recherches entre elles, ni décider d'un seuil d'acceptation.

### Le mécanisme retenu

Le score est **normalisé entre 0 et 1** et mesure la couverture de la requête.
La règle est simple :

- chaque mot significatif de la requête compte **une fois** ;
- un mot retrouvé dans le **nom** de la technique vaut plein tarif ;
- un mot retrouvé seulement dans la **description** vaut 0,35, parce qu'une
  description est longue et qu'y trouver un mot est beaucoup moins
  discriminant ;
- si la requête complète apparaît telle quelle dans le nom, un bonus de 0,15
  s'ajoute ;
- le total est ramené à 1,0 au maximum.

Deux seuils sont documentés et **rappelés dans chaque réponse** :

```json
"seuils": { "fort": 0.6, "faible": 0.3 }
```

### Le score se lit directement

```
"dumping"                   tokens=[dump]                    → T1003  1.0
                            matched={"name":["dump"]}
                            le seul mot de la requête est dans le nom : 1/1

"credential dumping"        tokens=[credential, dump]        → T1003  1.0
                            matched={"name":["credential","dump"]}
                            les deux mots sont dans le nom : 2/2

"lsass credential dumping"  tokens=[credential, dump, lsass] → T1003  0.667
                            matched={"name":["credential","dump"]}
                            deux mots sur trois : 2/3 = 0,667
```

Le modèle voit donc non seulement le score, mais **pourquoi** il vaut cela : le
mot `lsass` n'est pas dans le nom `OS Credential Dumping`. C'est ce qui
l'autorise à préférer T1003.001 `LSASS Memory` s'il dispose d'une preuve que
LSASS était bien en cause.

### Les preuves écartent le bruit

```
search_techniques("mimikatz")
→ T1003.001  LSASS Memory              0.35  matched_in=["description"]  matched={"description":["mimikatz"]}
  T1003.002  Security Account Manager  0.35  matched_in=["description"]  matched={"description":["mimikatz"]}
  T1003.004  LSA Secrets               0.35  matched_in=["description"]  matched={"description":["mimikatz"]}
```

Trois candidats à égalité, tous à 0,35, tous justifiés uniquement par une
mention dans la description. Le modèle lit `matched_in: ["description"]` et
sait immédiatement qu'aucun de ces candidats ne porte ce mot dans son nom :
`mimikatz` est un outil qui sert à plusieurs techniques, pas un comportement.
Sans le champ de preuve, trois scores identiques ne se départageraient pas.

### La correspondance par mots entiers, en pratique

```
v1.1  mitre_search("port")  →  331 candidats
      2e position : T1505.002  Transport Agent   41 points   (trans-PORT)
                    T1547.005  Security Support Provider     (sup-PORT)
                    T1535      Unused/Unsupported Cloud Regions
                    T1055.002  Portable Executable Injection

v2.0  search_techniques("port")  →  37 candidats, aucun faux positif
      T0885      Commonly Used Port   1.0
      T1571      Non-Standard Port    1.0
      T0846.001  Port Scan            1.0
      T1205.001  Port Knocking        1.0
      T1547.010  Port Monitors        1.0
```

`Security Support Provider` a disparu des résultats de `port`, mais reste
parfaitement trouvable par sa vraie requête : `security support provider`
→ T1547.005, score 1,0.

À noter que le champ `matched_in` de la v1.1 indiquait `name` pour
`Transport Agent` : il disait *où* la suite de lettres était tombée, pas qu'il
s'agissait d'un mot. Le garde-fou censé protéger le modèle le trompait.

### La racinisation, et pourquoi elle doit être symétrique

Une racinisation ramène les variantes d'un mot à une forme commune :
`dumping`, `dumped` et `dumps` deviennent tous `dump`. Elle est appliquée **de
façon identique à la requête et au catalogue**. C'est indispensable : si la
requête est au singulier et le catalogue au pluriel, sans racinisation
symétrique, il n'y a aucune correspondance.

| Requête | Catalogue | Racine commune |
|---|---|---|
| `file` | `files` | `fil` |
| `service` | `services` | `servic` |
| `name` | `names`, `named` | `nam` |
| `schedule` | `scheduled` | `schedul` |
| `credential` | `credentials` | `credential` |
| `dump` | `dumping` | `dump` |

Et les mots qui doivent rester distincts le restent : `port` ≠ `support`,
`lsa` ≠ `lsass`, `name` ≠ `namespace`. Le doublement de consonne est protégé,
donc `access` ne devient pas `acces`.

Vérification, même requête au singulier puis au pluriel :

```
"scheduled task"    → T1053     1.0      "schedule task"      → T1053     1.0
"service execution" → T1569.002 1.0      "services execution" → T1569.002 1.0
"file deletion"     → T1070.004 1.0      "files deletion"     → T1070.004 1.0
"dumping credential"→ T1003     1.0      "dump credentials"   → T1003     1.0
```

---

## Point 3 — Vérification obligatoire avec `get_technique`

### Ce que le point signifie

`search_techniques` ne conclut jamais. Il **propose**. Tout candidat retenu
doit être confirmé par un appel à `get_technique` avant d'être affirmé dans une
réponse.

### Pourquoi ce n'est pas une formalité

La recherche ne voit que le nom et la description. Elle ne sait pas dans quelle
matrice se trouve la technique, à quelle tactique elle se rattache, sur quelles
plateformes elle s'applique, ni comment on la détecte. Un candidat peut être
parfait sur le plan lexical et complètement inadapté au signal analysé.

La démonstration la plus nette est la requête `remote services` :

```
search_techniques("remote services")
  T0822  External Remote Services          1.0   matrix=ICS
  T0866  Exploitation of Remote Services   1.0   matrix=ICS
  T0886  Remote Services                   1.0   matrix=ICS
  T1021  Remote Services                   1.0   matrix=Enterprise
  T1133  External Remote Services          1.0   matrix=Enterprise
```

Cinq candidats à égalité parfaite, **1,0 pour tous les cinq**. Deux d'entre eux
portent exactement le même nom, `Remote Services`, et ce sont deux techniques
différentes. La recherche ne peut pas trancher ; elle n'est pas censée le
faire. La vérification, elle, tranche :

```
get_technique("T1021")   matrix=Enterprise
  tactiques   : Lateral Movement
  plateformes : Linux, macOS, Windows, IaaS, ESXi
  8 sous-techniques, 1 stratégie de détection, 6 mitigations, 3 groupes connus

get_technique("T0886")   matrix=ICS
  tactiques   : Initial Access, Lateral Movement
  plateformes : None (technique industrielle, non liée à un OS)
  0 sous-technique, 1 stratégie de détection, 9 mitigations
```

Deux techniques homonymes, deux mondes différents, et même des tactiques
différentes : T0886 couvre aussi l'accès initial, T1021 non. Choisir l'une ou
l'autre sur le seul score revient à tirer à pile ou face.

### Le volume d'information en jeu

La recherche renvoie un extrait volontairement court pour rester économe :

```
extrait de recherche pour T1021 :    97 caractères
description complète via get_technique : 1520 caractères
```

Soit un facteur seize. L'extrait sert à **trier** des candidats, pas à conclure
sur l'un d'eux.

### Comment c'est encodé

L'alinéa 3 de la description de `search_techniques` l'écrit au modèle :
*« VERIFIER chaque candidat retenu avec get_technique avant d'affirmer un
mapping »*. La description de `get_technique` le redit dans l'autre sens :
*« Detail complet d'une technique […] pour CONFIRMER un candidat de
mapping »*. Le nom même du champ retourné par la recherche, `results`, est
accompagné de `matched` et de `snippet`, jamais d'une conclusion.

---

## Point 4 — Parente d'abord, sous-technique seulement sur preuve

### Ce que le point signifie

À score égal, la **technique parente** est classée avant ses sous-techniques.
Le modèle ne doit retenir une sous-technique que si l'évidence dont il dispose
la confirme spécifiquement.

### Pourquoi

C'est la règle de précision recommandée par le CISA et par MITRE dans leurs
guides de mapping. Le raisonnement est le suivant : dire « vol d'identifiants
système » (T1003) quand on a observé un vol d'identifiants est **vrai**. Dire
« vol d'identifiants depuis la mémoire de LSASS » (T1003.001) quand on n'a pas
la preuve que LSASS était en cause est **peut-être faux**. Entre une
affirmation vraie et une affirmation plus précise mais risquée, un mapping
choisit la première. La précision supplémentaire doit être payée par une
preuve, pas devinée.

### Le mécanisme

Le tri se fait sur trois critères successifs, dans cet ordre : score
décroissant, puis **statut de sous-technique** (les parentes d'abord), puis
identifiant croissant. Le troisième critère garantit que deux exécutions
identiques renvoient exactement la même liste dans le même ordre — le tri est
déterministe, ce qui est une condition pour qu'une analyse soit reproductible.

### Mesures

```
"scheduled task"
→ T1053      (parente)  1.0     ← à égalité de score, la parente passe devant
  T1053.005  (sous)     1.0
  T0821      (parente)  0.5

"process injection"
→ T1055      (parente)  1.0
  T1055.001  (sous)     0.675
  T1055.002  (sous)     0.675

"command and scripting interpreter"
→ T1059      (parente)  1.0
  T1202      (parente)  0.567
```

La règle ne bloque pas les sous-techniques quand la preuve est là. Si la
requête porte l'élément discriminant, la sous-technique remonte
légitimement en tête :

```
"lsass memory"
→ T1003.001  LSASS Memory  (sous)  1.0     ← la preuve est dans la requête
  T1055.009  Proc Memory   (sous)  0.5
```

C'est exactement le comportement attendu : la sous-technique gagne parce que
l'évidence — le mot `lsass` — la désigne, pas parce qu'elle était mieux placée
dans la liste.

---

## Point 5 — Ne pas forcer : l'absence de mapping est une conclusion valide

### Ce que le point signifie

Quand aucune technique ne correspond, la bonne réponse est « aucun mapping ».
Le serveur le dit explicitement plutôt que de laisser le modèle face à une
liste vide qu'il pourrait être tenté de meubler.

### Pourquoi c'est un point de méthode et pas un détail

Un modèle de langage placé devant une liste de candidats médiocres a une
tendance naturelle à en choisir un : il a été sollicité, il produit une
réponse. En mapping TTP, c'est précisément le comportement à éviter, parce
qu'un identifiant ATT&CK faux ne se corrige jamais en aval — il est recopié
dans le rapport, agrégé dans les statistiques, et sert de base à des décisions.
Un « je ne trouve pas » est récupérable, un faux positif ne l'est pas.

### Le mécanisme

Deux notes automatiques sont ajoutées à la réponse :

- **aucun candidat** : `"aucun candidat : l'absence de mapping est une
  conclusion valide"` ;
- **uniquement des scores faibles**, c'est-à-dire meilleur score sous 0,3 :
  `"correspondances faibles uniquement : l'absence de mapping est une
  conclusion valide"`.

La règle est en outre écrite dans la description de l'outil, donc lue par le
modèle avant même l'appel : *« Une liste vide ou uniquement des scores faibles
signifie 'pas de mapping' : conclusion valide, ne pas forcer. »*

### Mesures

```
"imprimante thermique defectueuse"     →   0 candidat
    note: aucun candidat : l'absence de mapping est une conclusion valide

"zzzqqq"                               →   0 candidat
    note: aucun candidat : l'absence de mapping est une conclusion valide

"quantum blockchain toaster"           →   2 candidats, meilleur 0.117
    note: correspondances faibles uniquement : l'absence de mapping est une conclusion valide

"extraction des mots de passe Windows" → 225 candidats, meilleur 0.27
    note: correspondances faibles uniquement : l'absence de mapping est une conclusion valide
```

Le quatrième cas est le plus utile à comprendre : 225 candidats, ce qui a
l'air d'une abondance de réponses, mais le meilleur plafonne à 0,27. Le nombre
de candidats ne veut rien dire ; seul le score compte, et la note le rappelle.

### Une zone grise, dite franchement

La note automatique ne se déclenche qu'en dessous de 0,3. Entre 0,3 et 0,6, le
serveur ne commente pas :

```
"employee birthday party"  →  88 candidats, meilleur 0.333, aucune note
```

0,333 n'est pas un candidat fort — le seuil est à 0,6 — mais le serveur ne
l'écrit pas. C'est au modèle d'appliquer le seuil qu'il trouve dans le champ
`seuils` de la réponse. Cette zone intermédiaire est le point où la lecture
des preuves (point 2) et la vérification (point 3) restent indispensables.

---

## Point 6 — Identifiants révoqués : redirection au lieu d'erreur

### Le problème

MITRE retire régulièrement des techniques de son catalogue et les remplace par
d'autres. `T1086` (PowerShell) a été remplacée par `T1059.001`. La release 19.2
compte **158 remplacements** de ce type.

Un rapport de renseignement écrit en 2019 cite encore `T1086`. Un ticket de
SOC, une règle de détection, un tableau de correspondance interne aussi. La
v1.1 élimine les objets révoqués dès la lecture du fichier, donc l'information
de remplacement est perdue :

```
v1.1  mitre_technique("T1086")  →  { "error": "Technique 'T1086' non trouvee" }
```

L'analyse s'arrête là, et le modèle n'a aucun moyen de savoir si l'identifiant
est faux, s'il appartient à une autre matrice, ou s'il a simplement changé de
nom.

### Le mécanisme

Les relations `revoked-by` publiées par MITRE sont lues et transformées en
redirections explicites. Un point mérite d'être détaillé : MITRE chaîne parfois
**plusieurs révocations successives**. Les chaînes réelles trouvées dans la
19.2 :

```
T1073  →  T1574.002  →  T1574.001
T1150  →  T1547.011  →  T1647
T1162  →  T1547.011  →  T1647
```

Une redirection brute renverrait donc le modèle vers `T1574.002`, qui est
elle-même révoquée et n'existe pas dans la base : le modèle ferait un aller
pour rien et se retrouverait devant une erreur au deuxième appel. Les chaînes
sont donc **résolues transitivement** jusqu'à la cible finale, avec une limite
anti-boucle.

### Mesures

```
get_technique("T1086") → redirect vers T1059.001   (remplacant_vivant: true)  [PowerShell]
get_technique("T1073") → redirect vers T1574.001   (remplacant_vivant: true)  [DLL Side-Loading]
get_technique("T1150") → redirect vers T1647       (remplacant_vivant: true)  [Plist Modification]

total : 158 redirections, dont 0 qui n'aboutit pas à une technique vivante
```

La redirection n'est pas limitée à `get_technique`. La recherche redirige
aussi, et le dit :

```
search_techniques("T1086")
→ note: "'T1086' (PowerShell) est revoquee, remplacee par T1059.001 :
   recherche redirigee"
   1er résultat : T1059.001  (1.0)   2e : T1059  (0.7)

get_mitigations("T1086")
→ { "redirect": true, "replaced_by": "T1059.001" }
```

Le champ `remplacant_vivant` permet au modèle de vérifier lui-même que la cible
existe réellement avant de la citer.

### Limite assumée

Certaines techniques sont marquées obsolètes par MITRE **sans** relation de
remplacement publiée. Elles n'ont donc pas de redirection possible :

```
get_technique("T1055.006")  →  "Technique 'T1055.006' non trouvee"
```

Le serveur ne peut pas inventer un remplaçant que MITRE n'a pas désigné.

---

## Point 7 — Ne jamais mélanger les deux mondes

### Ce que le point signifie

Enterprise décrit l'informatique de bureau, ICS décrit les systèmes
industriels. Un signal issu d'un poste Windows ne doit jamais être rattaché à
une technique industrielle, et réciproquement. Le serveur fournit deux
garde-fous pour cela : un filtre de matrice sur la recherche, et un
avertissement systématique sur les noms de tactiques ambigus.

### Pourquoi c'est un vrai risque et pas une précaution théorique

Les deux catalogues emploient le même vocabulaire pour des choses différentes.
Une recherche non filtrée mélange donc les deux mondes avec des scores
strictement identiques. Mesuré :

```
search_techniques("valid accounts")
→ T0859  Valid Accounts   1.0   ICS
  T1078  Valid Accounts   1.0   Enterprise        ← même nom, même score, deux mondes

search_techniques("data destruction")
→ T0809  Data Destruction 1.0   ICS
  T1485  Data Destruction 1.0   Enterprise

search_techniques("remote services")
→ T0822, T0866, T0886  1.0  ICS
  T1021, T1133         1.0  Enterprise
```

Rien dans le score ne permet de choisir. Sans filtre, le classement dépend de
l'ordre alphabétique des identifiants, ce qui place systématiquement les
techniques ICS (`T0***`) devant les Enterprise (`T1***`) — un biais purement
mécanique qui n'a aucun sens analytique.

### Le mécanisme : le filtre de matrice

Une fois le monde déterminé par l'analyse du signal, le filtre rend le mélange
impossible :

```
search_techniques("valid accounts", matrix="ICS")        → T0859  1.0
search_techniques("valid accounts", matrix="Enterprise")  → T1078  1.0
```

Le filtre accepte `Enterprise` et `ICS`, ainsi que les formes courantes `IT`,
`OT` et `SCADA` :

```
matrix="SCADA" → ICS         matrix="ot" → ICS          matrix="IT" → Enterprise
```

Et une valeur non reconnue **lève une erreur explicite** au lieu de renvoyer
silencieusement zéro résultat, ce que faisait la v1.1 :

```
search_techniques("powershell", matrix="Mars")
→ { "error": "matrice 'Mars' inconnue - valeurs acceptees :
              Enterprise, ICS (ou IT, OT, SCADA)" }
```

La différence est importante : une liste vide se lit comme « ce comportement
n'existe pas dans ATT&CK », alors que la cause réelle était une faute de
frappe dans un paramètre.

### Le mécanisme : les tactiques homonymes

Neuf noms de tactiques désignent **deux tactiques différentes** selon la
matrice. Ce ne sont pas des variantes, ce sont des objets distincts avec des
identifiants distincts et des listes de techniques distinctes :

| Nom | Enterprise | ICS |
|---|---|---|
| Initial Access | TA0001 | TA0108 |
| Execution | TA0002 | TA0104 |
| Persistence | TA0003 | TA0110 |
| Privilege Escalation | TA0004 | TA0111 |
| Discovery | TA0007 | TA0102 |
| Lateral Movement | TA0008 | TA0109 |
| Collection | TA0009 | TA0100 |
| Command and Control | TA0011 | TA0101 |
| Impact | TA0040 | TA0105 |

Un modèle qui raisonne sur des noms tombera fatalement dans le piège. Le
serveur répond donc, mais avertit toujours :

```
get_tactic("Persistence")
→ { "id": "TA0003", "matrix": "Enterprise", "technique_count": 113,
    "homonyme_autre_matrice": [ { "id": "TA0110", "matrix": "ICS" } ] }

get_tactic("Persistence", matrix="OT")
→ { "id": "TA0110", "matrix": "ICS" }
```

Il ne choisit jamais en silence : soit la matrice est précisée, soit
l'homonyme est signalé.

### Le cloisonnement interne

Le risque ne s'arrête pas à l'interface. Les deux catalogues utilisent les
mêmes **noms courts** internes pour leurs tactiques (`persistence`,
`execution`, `initial-access`…). Si le rattachement d'une technique à sa
tactique se faisait par simple correspondance de nom court, une technique
industrielle serait reliée à la tactique Enterprise homonyme, et le mapping
serait faux au niveau tactique sans que rien ne le signale.

Le rattachement est donc effectué **au sein de la matrice de la technique**,
jamais par nom seul. Vérifié sur la base réelle : **988 liens
tactique-technique, 0 rattachement croisé**.

---

## Point 8 — Traçabilité : `db_version` dans chaque réponse

### Le problème

MITRE publie des versions numérotées de son catalogue. Un mapping produit sur
la 17.1 et un mapping produit sur la 19.2 ne sont pas comparables, parce que le
catalogue a changé entre les deux. Ce n'est pas un détail : entre ces deux
releases, **57 techniques ont été ajoutées et 25 retirées**, et des tactiques
ont changé de nom.

La v1.1 télécharge depuis un dépôt qui **ne publie pas le numéro de release** —
vérifié : aucun objet `x-mitre-collection` dans ces fichiers. Elle ne peut donc
indiquer que la date de son propre téléchargement, ce qui ne dit rien du
contenu réel de la base.

### Démonstration : la même question, deux réponses

```
--- catalogue 17.1 ---
tactiques Enterprise (14) :
  Reconnaissance, Resource Development, Initial Access, Execution, Persistence,
  Privilege Escalation, Defense Evasion, Credential Access, Discovery,
  Lateral Movement, Collection, Command and Control, Exfiltration, Impact

get_tactic("TA0005")  → "Defense Evasion"
get_technique("T1211") → "Exploitation for Defense Evasion", tactique : Defense Evasion
search_techniques("stealth") → T1548.005 à 0.35   (du bruit)

--- catalogue 19.2 ---
tactiques Enterprise (15) :
  ... Privilege Escalation, Stealth, Defense Impairment, Credential Access, ...

get_tactic("TA0005")  → "Stealth"
get_tactic("TA0112")  → "Defense Impairment"      (n'existait pas)
get_technique("T1211") → "Exploitation for Stealth", tactique : Stealth
search_techniques("stealth") → T1211 à 1.0
```

Le **même identifiant** `TA0005` et la **même technique** `T1211` portent deux
noms différents selon la release. Un rapport qui dit « tactique Defense Evasion
(TA0005) » et un rapport qui dit « tactique Stealth (TA0005) » sont tous les
deux justes — dans leur release respective. Sans le numéro de release, il est
impossible de savoir lequel on lit.

### Le mécanisme

La source bascule vers **`attack-stix-data`**, le dépôt STIX canonique de
MITRE, seul à porter l'objet `x-mitre-collection` contenant le numéro de
release et sa date. Ce numéro est rappelé dans **chaque réponse de chaque
outil**, y compris dans les réponses d'erreur :

```json
"db_version": { "Enterprise": "19.2", "ICS": "19.2" }
```

Vérifié : **11 outils sur 11** portent le champ, ainsi que les réponses
d'erreur — `get_technique("T9999")` renvoie l'erreur *et* la version de la
base.

`mitre_stats` complète avec l'âge du cache et un drapeau `stale` au-delà de
30 jours, et le journal d'audit trace la release au démarrage et à chaque
téléchargement :

```jsonl
{"event":"db_loaded","matrix":"Enterprise","source":"cache","release":"19.2","techniques":697}
{"event":"server_start","version":"2.0","db_version":{"Enterprise":"19.2","ICS":"19.2"}}
```

Un mapping produit avec ce serveur est donc daté d'une release précise, ce qui
est la condition pour qu'une étude soit reproductible.

---

## Complément : les filtres de contexte `platform` et `tactic`

En plus de `matrix` (point 7), `search_techniques` accepte deux filtres
nouveaux qui réduisent l'espace de recherche avant même le calcul du score.

```
search_techniques("dumping", tactic="credential-access")
→ T1003  1.0     (les techniques hors credential-access sont écartées)

search_techniques("scheduled task", platform="Windows")
→ T1053  1.0, puis T1053.005
```

`tactic` accepte un identifiant (`TA0006`) ou un nom court
(`credential-access`). `platform` accepte les valeurs publiées par MITRE
(`Windows`, `Linux`, `macOS`, `IaaS`, `ESXi`…). Ces filtres servent quand le
contexte du signal est connu : inutile de proposer des techniques Linux pour
un journal d'événements Windows.

---

# Partie III — Surface d'outils

## Nouvelle nomenclature

La nomenclature devient **`get_*`** pour les outils de consultation, plus
`search_techniques` pour la recherche et `mitre_stats` / `mitre_update` pour
l'administration. Elle est plus lisible pour un modèle et alignée sur les
conventions MCP courantes : un nom qui commence par `get_` annonce une lecture,
un nom qui commence par `search_` annonce une proposition à vérifier.

**Douze outils** sont exposés dans `tools/list` :

| Outil | Rôle |
|---|---|
| `search_techniques(query, limit?, matrix?, platform?, tactic?)` | Propose des candidats scorés avec preuves |
| `get_technique(id)` | Confirme un candidat ; redirige les identifiants révoqués |
| `get_tactics(matrix?)` | Les tactiques dans l'ordre officiel de la kill chain |
| `get_tactic(id, matrix?)` | Une tactique et ses techniques ; signale l'homonyme |
| `get_mitigations(technique_id)` | Les contre-mesures d'une technique |
| `get_mitigation(id)` | Une contre-mesure et les techniques qu'elle couvre |
| `get_groups(technique_id?, matrix?)` | Les groupes APT |
| `get_group(id)` | Un groupe APT en détail |
| `get_software(technique_id?)` | Les software/malware |
| `get_datasources(query, matrix?)` | Les techniques observables depuis une source de logs |
| `mitre_stats()` | État du serveur, releases, modèle de détection, fraîcheur |
| `mitre_update()` | Re-télécharge les deux matrices |

`get_mitigations` et `get_mitigation` sont les deux sens du même lien et sont
complémentaires : le premier part d'une technique pour produire une
recommandation, le second part d'une contre-mesure pour l'élargir à toutes les
techniques qu'elle couvre.

## Alias de compatibilité

**Dix alias** correspondant aux noms de la v1.1 restent acceptés en entrée :
`mitre_search`, `mitre_technique`, `mitre_tactics`, `mitre_tactic`,
`mitre_mitigations`, `mitre_mitigation`, `mitre_groups`, `mitre_group`,
`mitre_software`, `mitre_datasources`.

Ils sont résolus au moment de l'exécution et **n'apparaissent pas dans
`tools/list`**, donc ils ne consomment aucun contexte côté modèle : le modèle
voit douze outils, pas vingt-deux. Une intégration écrite pour la v1.1
continue d'appeler ses outils par leur nom d'origine sans modification.

## Normalisation des identifiants

MITRE ne connaît que la forme à trois décimales, `T1059.001`. Les rapports, les
tickets et les humains écrivent aussi `T1059.1` ou `t1059.01`. La normalisation
de la v1.1 est conservée et étendue à tous les outils qui prennent un
identifiant de technique, ainsi qu'aux identifiants repérés à l'intérieur
d'une requête de recherche :

```
get_technique("t1059.1")    → T1059.001  PowerShell
get_technique("T1003.1")    → T1003.001  LSASS Memory
get_mitigations("t1003.1")  → les 7 contre-mesures de T1003.001
```

---

# Partie IV — Défauts internes corrigés

Quatre défauts de la v1.1 sans rapport avec le catalogue MITRE.

**Deux outils donnaient deux nombres différents sous le même nom de champ.**
Pour la tactique `TA0003`, `mitre_tactics` annonçait 113 techniques et
`mitre_tactic` 22, parce que le second filtrait silencieusement les
sous-techniques. Un modèle qui enchaînait les deux appels voyait une
contradiction. La v2.0 rend les deux nombres, explicitement nommés :

```
get_tactic("TA0003")
→ "technique_count": 113, "parent_technique_count": 22
```

**La résolution par nom partiel était silencieuse.** `mitre_mitigation("Access")`
renvoyait la première contre-mesure dont le nom contient « access », sans
indiquer que la correspondance était approximative ni qu'il y avait d'autres
candidats. La v2.0 signale le mode de résolution et fournit la liste :

```
get_mitigation("Access")
→ { "id": "M0801", "name": "Access Management",
    "resolution": { "mode": "partiel", "candidats": [ 4 entrées ] } }
```

**Le serveur retéléchargeait le catalogue à chaque appel d'outil** tant que la
base n'était pas prête, avec un délai d'attente réseau de 90 secondes par
matrice. Un réseau qui ne répond pas pouvait bloquer chaque appel près de trois
minutes, et le client MCP abandonnait avant. La v2.0 applique une temporisation
de 60 secondes entre deux tentatives et répond immédiatement, entre-temps, par
un message explicite :

```
→ { "error": "Base MITRE indisponible ou incomplete",
    "details": ["matrice ICS absente ou vide"] }
```

**Les erreurs d'arguments.** En plus du message, la réponse donne les
paramètres attendus et ceux qui sont obligatoires, ce qui permet au modèle de
corriger son appel sans tâtonner :

```
→ { "error": "Arguments invalides: get_technique() missing 1 required
              positional argument: 'id'",
    "attendus": ["id"], "requis": ["id"] }
```

---

# Partie V — Garde-fous conservés et renforcés

Ces protections existaient en v1.1 ; elles sont conservées et durcies.

**Cache incomplet ou illisible refusé.** Une base n'est déclarée prête que si
chaque matrice attendue est présente, peuplée et reliée à ses tactiques. Un
fichier tronqué, vide ou illisible déclenche un retéléchargement au lieu d'un
démarrage sur une base amputée. Le risque écarté est précis : un serveur qui
annoncerait deux matrices tout en n'en servant qu'une amènerait le modèle à
chercher des signaux informatiques dans la matrice industrielle, et à conclure
« aucune attaque détectée » sans pouvoir s'en apercevoir — c'est-à-dire à
produire, en toute bonne foi, la conclusion du point 5 pour une raison qui n'a
rien à voir avec les données. Testé sur trois scénarios :

```
cache Enterprise tronqué → "Cache Enterprise illisible (...) : retelechargement"
                         → 794 techniques, OK
cache ICS vide (0 octet) → "Telechargement MITRE ICS..." → 794 techniques, OK
une matrice injoignable  → "Base incomplete : matrice ICS absente ou vide"
                         → ECHEC, code de sortie 1
```

**La base est préservée en cas d'échec de mise à jour.** `mitre_update`
télécharge et analyse les deux bundles dans une base neuve, vérifie son
intégrité, et ne remplace la base en service qu'en cas de succès complet :

```
mitre_update() avec le réseau coupé
→ { "status": "error", "errors": {...}, "base_preservee": true }
   avant : 794 techniques   |   après : 794 techniques
```

Le fichier de cache continue d'être écrit par remplacement atomique : le
téléchargement écrit un fichier `.tmp` puis le renomme, de sorte qu'une coupure
ne peut pas laisser un JSON corrompu sur le disque.

**`--test` vérifie au lieu d'afficher.** Il détaille chaque matrice, puis sort
en code 1 si une matrice est vide, si les liens tactique-technique sont
absents, si la couverture de détection est anormale, si l'index des sources est
vide, ou si une réciprocité est rompue. Il est utilisable tel quel en
intégration continue, et couvre la classe de régression la plus dangereuse pour
ce serveur : celle qui vide silencieusement une relation sans produire la
moindre erreur.

**Fusion des groupes et software communs aux deux matrices.** Les techniques,
tactiques et mitigations occupent des espaces d'identifiants disjoints entre
les deux domaines (`T1***` contre `T0***`, `TA00**` contre `TA01**`, `M1***`
contre `M0***`). Les groupes et les software, eux, partagent leurs
identifiants : 12 groupes et 17 software sont publiés dans les deux bundles.
Ils sont fusionnés et portent une **liste** `matrices`, là où les autres objets
portent une **chaîne** `matrix`. La distinction est volontaire : une valeur
composite du type `"Enterprise+ICS"` obligerait le modèle à interpréter une
troisième valeur non documentée, alors que la méthode lui demande précisément
de ne jamais mélanger les deux mondes.

```
get_group("G0034")  →  "matrices": ["Enterprise", "ICS"]
```

**Journal d'audit JSONL.** Démarrage, arrêt, téléchargements avec leur durée,
chargement du cache, cache invalide, appels d'outils avec leur statut. Écriture
par un thread dédié qui ne bloque jamais la réponse, file drainée intégralement
à l'arrêt. Répertoire redéfinissable par `MITRE_LOGS`, désactivable par
`--no-audit`.

---

# Partie VI — Économie de contexte

Chaque réponse du serveur est lue par un modèle de langage, et tout ce qu'il
lit consomme du budget. La v1.1 sérialise avec de l'indentation, renvoie les
descriptions entières et restitue l'information de détection trois fois (texte,
structure, listes de sources).

La v2.0 compacte le JSON, nettoie les descriptions des citations
`(Citation: …)` et des liens markdown, limite les extraits de recherche à la
première phrase, et borne les listes annexes sous la forme
`{count, items, truncated}` — le compte total reste exact, seule la liste est
plafonnée, et le modèle sait qu'elle l'est.

Mesuré, mêmes demandes sur les deux serveurs :

| Demande | v1.1 | v2.0 |
|---|---|---|
| Détail d'une technique (`T1003.001`) | 15 141 car. (~3 785 tokens) | 6 437 car. (~1 609) |
| Détail d'une technique (`T1078`) | 16 898 car. (~4 224 tokens) | 6 418 car. (~1 604) |
| Une recherche | 16 805 car. (~4 201 tokens) | 3 717 car. (~929) |
| Une source de logs | 11 696 car. (~2 924 tokens) | 5 480 car. (~1 370) |
| Une tactique (`TA0003`) | 2 800 car. (~700 tokens) | 1 772 car. (~443) |

Ce n'est pas un gain cosmétique. Un mapping complet enchaîne une recherche,
deux ou trois vérifications et une demande de contre-mesures : environ
15 000 tokens en v1.1, environ 5 000 en v2.0. La différence détermine si
l'analyse tient dans une conversation ou si elle sature le contexte à
mi-parcours.

---

# Partie VII — Vérification

Sortie de `python mcp_mitre.py --test` sur la release 19.2 :

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
Outils (12) / Alias (10)
OK
```

Détail par matrice : 44 mitigations Enterprise et 52 ICS ; 176 groupes
Enterprise et 14 ICS dont 12 communs ; 825 software Enterprise et 23 ICS dont
17 communs ; 301 techniques parentes et 493 sous-techniques.

Chargement à froid depuis le cache : 921 ms pour 55 Mo. Cinquante recherches
consécutives : 32 ms.

Les réciprocités vérifiées sont : tactique ↔ technique cloisonnée par matrice,
parente ↔ sous-technique, mitigation ↔ technique, groupe ↔ technique, et
aboutissement des redirections.

---

## Changements de contrat

| Avant (v1.1) | Après (v2.0) |
|---|---|
| Outils `mitre_*` (12) | Outils `get_*` (12), anciens noms acceptés comme alias |
| `detection` : chaîne de texte | `detections` : liste de stratégies avec analytics et sources de logs ; `legacy_detection` conserve le texte des anciens catalogues |
| `data_sources` + `log_sources` : deux listes, libellés pollués par `channel` | `data_sources` : une liste de libellés assainis |
| Score de recherche : entier sans échelle | Score normalisé [0..1], seuils 0,6 / 0,3 rappelés dans la réponse |
| `matched_in` : où la sous-chaîne est tombée | `matched` : les mots réellement trouvés, par champ ; `matched_in` conservé |
| Identifiant révoqué : « non trouvé » | Objet `redirect` explicite, cible finale vivante |
| Pas de version de catalogue dans les réponses | `db_version` dans chaque réponse |
| Filtre `matrix` inconnu : 0 résultat silencieux | Erreur explicite |
| Pas de filtre `platform` ni `tactic` | Deux filtres de contexte supplémentaires |
| `technique_count` ambigu selon l'outil | `technique_count` et `parent_technique_count` |
| Résolution par nom partiel silencieuse | Champ `resolution` avec la liste des candidats |
| Troncature : `{shown, total, truncated}` | Troncature : `{count, items, truncated}` |
| Source `mitre/cti` | Source `attack-stix-data` (release tracée) |
| Cache `MITRE_DB/attack.json` (base analysée, ~5 Mo) | Cache `MITRE_DB/enterprise-attack.json` et `ics-attack.json` (bundles STIX bruts, ~55 Mo) |

---

## Compatibilité et migration

Python 3.8 ou supérieur, bibliothèque standard uniquement, aucune dépendance
`pip`. Transport stdio local inchangé, configuration Claude Desktop identique.

Les variables d'environnement `MITRE_CACHE` et `MITRE_LOGS` et les options
`--test`, `--no-audit` et `--help` sont conservées.

L'ancien fichier `MITRE_DB/attack.json` peut être supprimé : il n'est plus lu.
En son absence, les deux bundles sont téléchargés au premier lancement, puis
réutilisés depuis le cache.

Les intégrations écrites pour la v1.1 continuent d'appeler leurs outils par
leur nom d'origine grâce aux alias. En revanche, **les scripts ou consignes qui
lisent les champs de réponse doivent être revus** : les changements de format
sont listés ci-dessus. En particulier, un prompt système rédigé pour la v1.1
doit être mis à jour sur deux points :

- il décrit la recherche comme fonctionnant par sous-chaînes, avec l'exemple
  « port matche support » : ce n'est plus vrai, et laisser cette consigne
  conduirait le modèle à se méfier de candidats désormais fiables ;
- il s'appuie sur `matched_in` seul, alors que `matched` donne maintenant les
  mots exacts trouvés dans chaque champ, ce qui est une information plus riche
  et plus sûre pour écarter le bruit.

---

## Limites connues

- Domaine Mobile non couvert.
- Les campagnes (`campaign`, 56 objets côté Enterprise) et les ressources
  industrielles (`x-mitre-asset`, 18 objets côté ICS) ne sont pas exposées.
- **La recherche reste lexicale et non sémantique.** Elle compare des mots, pas
  des sens. Une requête en français ou en anglais courant ne donne pas de
  résultat exploitable, et peut même renvoyer une réponse fausse avec un score
  élevé (voir le préalable de la partie II). Les requêtes doivent être
  formulées en vocabulaire ATT&CK, un comportement à la fois.
- La racinisation est volontairement légère et ne remplace pas un algorithme
  complet : `execute` et `execution` ne convergent pas.
- La note automatique d'absence de mapping ne se déclenche qu'en dessous de
  0,3 ; entre 0,3 et 0,6 le serveur ne commente pas, et c'est au modèle
  d'appliquer le seuil de candidat fort.
- Une technique marquée obsolète par MITRE sans relation de remplacement
  publiée ne peut pas être redirigée.
- Le cache n'expire pas automatiquement. `mitre_stats` signale son âge et lève
  un drapeau `stale` au-delà de 30 jours, mais ne retélécharge pas seul.
- Le vocabulaire ATT&CK évolue : la tactique `TA0005` s'appelle désormais
  « Stealth » et une tactique `TA0112` « Defense Impairment » a été introduite.
  Le serveur lit ces libellés dans le catalogue et suit donc le changement,
  mais les consignes rédigées sur l'ancienne nomenclature doivent être revues.
- Transport stdio uniquement, sans authentification ni exposition réseau. C'est
  le modèle normal d'un serveur MCP local ; la sécurisation et l'exposition
  réseau relèvent du jalon production.
