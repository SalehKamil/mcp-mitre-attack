# Erreurs & biais à éviter dans le mapping ATT&CK

> Chargé pour l'intention **B (Mapper)**. Combine les erreurs canoniques
> documentées par CISA/MITRE et les écueils propres aux modèles de langage
> (issus de la littérature d'évaluation LLM↔ATT&CK). Objectif : précision TTP
> de pointe.

## A. Les 3 erreurs canoniques de mapping (CISA)

### 1. Leaping to Conclusions (conclusion hâtive)
Décider d'un mapping sur des preuves insuffisantes.
- **Exemple** : mapper un malware utilisant les ports 80/443 vers
  `T1071.001` (Web Protocols) **sans avoir confirmé** l'usage du protocole
  HTTP/S. Le port n'implique pas le protocole.
- **Parade** : examiner les détails/artefacts, puis faire correspondre. S'il y a
  plusieurs techniques possibles, vérifier que la tactique s'aligne et écarter
  d'abord celles qui ne correspondent pas exactement. Processus itératif jusqu'à
  ne garder que les correspondances claires — ou constater le manque de preuve.

### 2. Missed Opportunities (occasions manquées)
Oublier des mappings impliqués ou peu visibles.
- **Exemple** : « accès à l'environnement via un VPN externe » mappe directement
  vers External Remote Services `T1133`, mais implique aussi potentiellement
  Valid Accounts `T1078` si des identifiants légitimes ont été abusés.
- **Parade** : chercher **tous** les comportements, y compris les mappings
  un-à-plusieurs. Noter les lacunes analytiques (ex. aucune info sur l'accès
  initial = à signaler explicitement).

### 3. Miscategorization (mauvaise catégorisation)
Choisir la mauvaise technique faute de saisir une distinction fine.
- **Exemple** : la capacité d'un malware à supprimer des fichiers arbitraires
  mappée vers Data Destruction `T1485` (tactique Impact) au lieu de
  Indicator Removal: File Deletion `T1070.004` (tactique Defense Evasion). La
  tactique change tout le sens.
- **Autres pièges de libellé proche** :
  - Software Packing `T1027.002` (Defense Evasion) ≠ Data Encoding `T1132`
    (Command and Control).
  - Masquerading `T1036` (général) ≠ Masquerade Task or Service `T1036.004`
    (usurpation d'une tâche/service précis).
- **Parade** : lister les techniques candidates, **lire attentivement** leurs
  descriptions (via `get_technique`), comparer, et chercher des cas d'usage de
  référence.

## B. Pièges propres aux LLM (à neutraliser activement)

Ces écueils sont documentés dans les évaluations de LLM sur le mapping ATT&CK et
justifient l'ancrage systématique sur le serveur MCP.

1. **Hallucination par similarité textuelle.** Les descriptions de techniques et
   sous-techniques se ressemblent fortement → le modèle produit un ID plausible
   mais faux. *Parade : ne jamais énoncer un ID sans l'avoir obtenu/confirmé par
   un appel d'outil.*

2. **Confusion numéro ↔ libellé.** Cas réel observé : un modèle mappe vers
   « T1556.004 : Bypass User Account Control » alors que le libellé réel de cet
   ID est « Modify Authentication Process: Network Device Authentication ». Le
   numéro était mémorisé de travers. *Parade : confirmer le **sens** via la
   description renvoyée par `get_technique`, pas seulement le numéro.*

3. **Mémoire périmée.** ATT&CK évolue à chaque release ; un ID mémorisé peut
   avoir changé, être déprécié ou révoqué. *Parade : `mitre_stats()` pour citer
   la version, et toujours lire la fiche à jour via l'outil.*

4. **Sur-déclenchement / mapping forcé.** Tendance à produire un mapping même
   quand l'entrée ne contient aucun comportement adverse étayé. *Parade :
   invariant « ne pas inférer » ; dire clairement quand rien n'est mappable.*

5. **Confiance non calibrée.** Énoncer un mapping incertain avec le même aplomb
   qu'un mapping solide. *Parade : indiquer un niveau de confiance et la preuve
   qui le justifie (voir formats-sortie.md).*

## C. Biais de reporting (à garder en tête, surtout en CTI)

Les rapports sources sont eux-mêmes biaisés ; en tenir compte avant de conclure :

- **Biais de nouveauté** — les techniques nouvelles/inhabituelles sont
  sur-rapportées.
- **Biais de visibilité** — chaque organisation ne voit qu'une partie des
  techniques.
- **Biais de producteur** — quelques organisations publient beaucoup et ne
  reflètent pas forcément l'ensemble de la communauté.
- **Biais de victime** — certains types de victimes rapportent (ou sont
  rapportés) plus que d'autres.
- **Biais de disponibilité** — les techniques bien connues d'un auteur sont
  citées plus souvent.

Conséquence : l'absence d'une technique dans un rapport ne prouve pas son
absence dans l'attaque. Mapper ce qui est **étayé**, signaler les **lacunes**.

## Checklist de vérification (à dérouler avant de livrer un mapping)

- [ ] Chaque ID énoncé a été obtenu/confirmé par un appel d'outil ?
- [ ] La description de l'outil correspond bien au comportement (sens, pas
      numéro) ?
- [ ] La tactique associée est cohérente avec la technique ?
- [ ] Les mappings un-à-plusieurs et implicites ont été cherchés ?
- [ ] La profondeur est correcte (sous-technique / technique / tactique) ?
- [ ] Les comportements non mappables / lacunes sont signalés ?
- [ ] La version ATT&CK est citée (`mitre_stats`) ?
- [ ] Matrice (Enterprise/ICS) précisée si pertinent ?
