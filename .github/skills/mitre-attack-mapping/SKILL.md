---
name: mitre-attack-mapping
description: Méthode outillée pour attribuer des identifiants MITRE ATT&CK (tactique, technique, sous-technique) à un comportement observé dans des journaux, alertes ou rapports, sur les matrices Enterprise et ICS. À utiliser dès qu'une tâche demande de mapper, classifier ou étiqueter une observation en identifiants ATT&CK (Txxxx, TAxxxx). Impose la vérification contre une base ATT&CK vivante (serveur MCP ou outils équivalents) quand elle est disponible, des règles de départage explicites, la déclaration des ambiguïtés et l'abstention motivée plutôt que l'invention. / Tool-grounded procedure for mapping observed behaviors to MITRE ATT&CK tactics, techniques and sub-techniques (Enterprise and ICS); use whenever a task requires assigning ATT&CK identifiers to an observation.
---

# Skill de mapping MITRE ATT&CK

## Principe

La base ATT&CK fait foi, pas la mémoire. Trois issues sont valides, et
seulement trois :

1. un mapping **vérifié** contre la base ;
2. un mapping **multiple documenté**, quand l'observation porte réellement
   plusieurs techniques ;
3. une **abstention motivée**, quand l'évidence ne suffit pas.

Un identifiant qui n'a pas été vu dans la sortie d'un outil pendant la session
n'est jamais une issue valide. Le score d'un moteur de recherche n'est jamais
une preuve : c'est une file de candidats à vérifier.

Ce skill rend la **procédure** déterministe et auditable. Il ne prétend pas
rendre le résultat infaillible : sur une observation qui porte deux techniques
à la fois, la « bonne » réponse dépend d'une convention d'étiquetage qui
appartient à l'hôte, pas au skill — d'où l'étape 0 et le protocole
d'ambiguïté de l'étape 5.

---

## 0. Inventaire des moyens et des conventions

Avant tout mapping, établir trois choses.

**Les outils.** Chercher parmi les outils disponibles ceux qui interrogent une
base ATT&CK : typiquement `search_techniques`, `get_technique`, `get_tactics`,
`get_tactic` (les noms peuvent varier : `mitre_search`, `attack_lookup`…
repérer les outils dont la description mentionne ATT&CK, techniques ou
tactiques). S'ils existent, le **mode outillé** s'applique : tout ce qui suit
en dépend. S'ils n'existent pas, passer en **mode dégradé** (fin du document).

**La version de la base.** La relever si un outil l'expose (`db_version`,
`mitre_stats`, bannière du serveur) et la reporter dans la réponse quand le
format s'y prête. Un mapping se rattache à une version d'ATT&CK.

**Les conventions de l'hôte.** Le workflow, le prompt système ou la tâche
peuvent fixer : la matrice à utiliser, le format de sortie, le niveau attendu
(technique parente ou sous-technique), et une **règle de co-occurrence**
(quelle étiquette retenir quand un moyen et son effet sont observés ensemble —
par exemple « l'interpréteur prime » ou « l'effet prime »). Ces conventions
priment sur les règles par défaut de ce skill. En leur absence, appliquer les
défauts de l'étape 5.

---

## 1. Isoler le comportement

Une recherche mappe **un** comportement atomique. Si l'observation en contient
plusieurs (une exécution, puis une exfiltration), les traiter séparément —
un mapping chacun, sauf si l'hôte demande un seul résultat, auquel cas
mapper le comportement central et signaler les autres.

Extraire et conserver le **fragment exact** qui porte le comportement (ligne
de commande, fonction protocolaire, chemin, nom de processus). Tout le reste
de la procédure se juge contre ce fragment, et il sera cité dans la réponse.

## 2. Fixer la matrice avant de chercher

La base ne connaît pas le contexte : elle ne sait de la matrice que ce qu'on
lui passe. **Toujours** renseigner le filtre de matrice de la recherche.

- L'hôte indique la matrice → l'utiliser telle quelle.
- Sinon : environnement industriel — automates, protocoles OT (Modbus, DNP3,
  S7comm, OPC, EtherNet/IP, BACnet), postes d'ingénierie, historians, HMI —
  → **ICS**. Tout le reste → **Enterprise**.
- Une même dénomination de technique peut exister dans les deux matrices
  (Valid Accounts, Screen Capture, Masquerading…). Si la réponse d'un outil
  signale des homonymes inter-matrices (champ `homonymes` ou équivalent),
  ne jamais trancher sans filtre de matrice explicite.

## 3. Rechercher

Construire la requête en **mots-clés du vocabulaire ATT&CK, en anglais**, qui
décrivent le comportement — pas la ligne de journal brute, pas une phrase.
Trois mots significatifs minimum ; inclure l'artefact le plus discriminant
(`lsass`, `-EncodedCommand`, `WRITE_MULTIPLE_COILS`, `kerberoast`…).

- Un seul mot n'est pas une requête de mapping : le score d'un moteur lexical
  y est trivialement gonflé.
- Zéro candidat ou uniquement des scores faibles → **une** reformulation
  (synonyme, artefact différent, niveau de description différent). Toujours
  rien → étape 7, abstention.
- Un résultat marqué comme simple pivot d'entité (« ce groupe utilise cette
  technique », `matched.pivot` ou équivalent) est une piste, pas un candidat.

## 4. Vérifier les candidats — jamais un seul

Consulter la fiche complète (`get_technique`) des **deux ou trois premiers**
candidats, pas seulement du premier. Pour chacun, confronter sa définition au
fragment cité : la fiche décrit-elle *ce* fragment, ou seulement sa famille ?

Règle d'écartement : **écarter le candidat classé premier exige de nommer,
dans la justification, l'élément du fragment qui l'exclut.** Sans un tel
élément, le premier candidat vérifié est retenu. Cette règle est le garde-fou
contre le remplacement silencieux d'un candidat exact par un candidat
familier.

## 5. Départager

Dans cet ordre, en s'arrêtant à la première règle qui tranche :

1. **Convention de l'hôte** (étape 0), si elle couvre le cas.
2. **Spécificité de l'artefact.** Un marqueur d'obfuscation ou d'encodage
   visible dans la commande (charge Base64, `-EncodedCommand`, décodage
   explicite) prime sur l'interpréteur qui la porte : l'artefact le plus
   spécifique est le plus discriminant.
3. **Fonction exacte avant famille.** Plusieurs techniques voisines d'une
   même tactique se distinguent par la fonction précise et la portée de
   l'action — en ICS notamment : lecture d'état d'un procédé, identification
   de points et de tags, collecte automatisée multi-équipements, détection du
   mode de marche, écriture de sorties, modification de paramètres sont des
   techniques distinctes. Ne pas rabattre sur la plus générale : consulter
   les fiches des techniques sœurs de la même tactique et choisir celle dont
   la définition nomme la fonction observée (le code fonction protocolaire,
   la répétition, le nombre d'équipements visés sont les discriminants).
4. **Co-occurrence réelle.** Si le même fragment porte véritablement deux
   techniques — un moyen et son effet (`sudo` + lecture de `/etc/shadow` ;
   un interpréteur + la découverte qu'il exécute) — et qu'aucune convention
   d'hôte ne tranche : retenir en principal la technique dont la fiche cite
   l'artefact observé dans ses procédures ou sa détection, et **déclarer
   l'autre en mapping secondaire** si le format de sortie le permet, ou dans
   la justification sinon. Ne jamais trancher sans le dire.
5. **Niveau.** La technique **parente** est le défaut. Une sous-technique ne
   se retient que si l'évidence la nomme spécifiquement. Répondre « aucune
   sous-technique » exige d'avoir vérifié, sur la fiche de la parente, que
   les sous-techniques existantes ne correspondent pas au fragment.

## 6. Contrôles obligatoires avant de répondre

Chaque contrôle se fait contre la base, pas de mémoire. Un échec renvoie à
l'étape 3 ou 7.

- [ ] L'identifiant retenu **existe** dans la base interrogée.
- [ ] Il appartient à la **matrice** fixée à l'étape 2.
- [ ] La **tactique** déclarée figure parmi les tactiques de la technique
      (fiche `get_technique` ou `get_tactic`).
- [ ] La **sous-technique**, le cas échéant, est rattachée à la technique
      déclarée (`Txxxx.yyy` sous `Txxxx`, et présente dans sa fiche).
- [ ] L'identifiant n'est **ni révoqué ni déprécié**. S'il est révoqué,
      suivre la redirection (`replaced_by`) et retenir le remplaçant vivant ;
      s'il est déprécié sans remplaçant, le dire et revenir à l'étape 3.
- [ ] L'identifiant a été **vu dans la sortie d'un outil de cette session**
      — c'est la définition de l'ancrage.

## 7. Abstention

S'abstenir est une réponse correcte quand : le fragment ne décrit pas un
comportement adverse identifiable ; deux reformulations n'ont produit aucun
candidat dont la définition couvre le fragment ; ou les outils sont
indisponibles et l'hôte exige des réponses vérifiées. L'abstention se motive
en une phrase (ce qui manque), et respecte le format de l'hôte (champs vides,
valeur dédiée…). Ne jamais combler une abstention par l'identifiant « le plus
proche ».

## 8. Réponse

Le **format de l'hôte prime toujours** — s'il impose un schéma, le respecter
exactement, sans texte autour. À défaut, produire :

```json
{
  "tactique": "TAxxxx",
  "technique": "Txxxx",
  "sous_technique": "Txxxx.yyy | aucune",
  "element_cite": "le fragment exact du journal",
  "justification": "artefact observé -> définition de la technique ; candidat écarté nommé le cas échéant",
  "secondaires": [{"technique": "Txxxx", "raison": "co-occurrence : ..."}],
  "verifications": {"base": "ATT&CK <version>", "matrice": "Enterprise|ICS",
                    "tactique_confirmee": true, "niveau_confirme": true,
                    "revocation": "aucune | Tyyyy remplace par Txxxx"}
}
```

La justification relie toujours le fragment cité à la définition de la
technique — jamais à une généralité (« correspond à de l'exécution »).

## 9. Pièges connus, mesurés en campagne

- **Rabattement générique** : la technique la plus générale d'une famille
  attire les cas fins (étape 5.3). Premier poste d'erreur en ICS.
- **Homonymes inter-matrices** : sans filtre, la mauvaise matrice peut sortir
  en tête avec un score parfait.
- **Identifiants historiques** : des pans entiers d'ATT&CK ont été renumérotés
  au fil des versions ; un identifiant appris peut être révoqué. Seule la
  redirection de la base fait foi.
- **Score ≠ probabilité** : un score lexical élevé sur une requête pauvre ne
  prouve rien ; la vérification de fiche tranche, pas le score.
- **Pivot d'entité** : « APT29 utilise T1003 » ne mappe pas votre journal.

## Mode dégradé — aucun outil ATT&CK disponible

Le skill ne peut alors rien vérifier. Selon la politique de l'hôte : soit
s'abstenir, soit répondre en **marquant explicitement** que le mapping est non
vérifié (mémoire du modèle, version d'ATT&CK inconnue, identifiants sujets à
révocation) — et dans ce cas ne jamais renseigner de champ de vérification.
Aucun des contrôles de l'étape 6 ne peut être simulé de mémoire.

## Ce que ce skill garantit, et ce qu'il ne garantit pas

Garanti, en mode outillé : aucun identifiant inventé, aucun identifiant hors
matrice, aucun identifiant révoqué, une trace de vérification, une procédure
identique d'une exécution à l'autre. Non garanti : la conformité à une clé
d'évaluation dont la convention de co-occurrence n'est pas écrite — ce cas est
détecté et déclaré (étape 5.4), il n'est pas devinable ; et le déterminisme du
modèle qui exécute la procédure.
