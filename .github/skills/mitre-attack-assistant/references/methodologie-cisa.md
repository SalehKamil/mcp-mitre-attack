# Méthodologie de mapping MITRE ATT&CK (d'après CISA & MITRE ATT&CK)

> Chargé pour l'intention **B (Mapper)**. Source : CISA, *Best Practices for
> MITRE ATT&CK Mapping*, v2 (janvier 2023, TLP:CLEAR). Adapté pour un assistant
> branché sur le serveur MCP `mitre` : chaque identifiant cité doit être
> confirmé par un appel d'outil.

## Les 4 niveaux ATT&CK (rappel)

- **Tactique** = le « pourquoi » (objectif de l'adversaire, ex. Credential Access).
- **Technique** = le « comment » (action menée pour atteindre l'objectif).
- **Sous-technique** = un « comment » plus granulaire (souvent spécifique à une
  plateforme ou un OS ; toutes les techniques n'en ont pas).
- **Procédure** = le « quoi » exact (mise en œuvre concrète : outil, commande).

Le framework n'est **pas linéaire** : un adversaire ne traverse pas les tactiques
de gauche à droite, et n'utilise pas forcément toutes les tactiques.

## Procédure en 6 étapes

Le point de départ peut varier (tactique ou technique d'abord) selon les
informations disponibles. L'ordre ci-dessous est le cas général.

1. **Trouver le comportement.** Chercher comment l'adversaire a interagi avec
   les plateformes et applications — pas les IOC (hash, IP, domaine). Repérer
   l'accès initial puis l'activité post-compromission. Attention au
   « living off the land » (détournement de fonctions système légitimes).

2. **Rechercher le comportement.** Si le contexte manque, se documenter pour
   comprendre l'action. Tous les comportements ne deviennent pas une technique,
   mais les détails techniques s'additionnent pour éclairer l'objectif global.
   Repérer les verbes d'action (« exécute une commande », « crée une
   persistance », « crée une tâche planifiée », « établit une connexion »).

3. **Traduire le comportement en tactique.** Se demander *pourquoi* l'action est
   menée (voler des données ? détruire ? élever ses privilèges ?). Identifier
   **toutes** les tactiques présentes, pas une seule.
   Avec le serveur : `get_tactics()` pour cadrer, `get_tactic(id)` pour lister
   les techniques d'une tactique retenue.

4. **Identifier la technique applicable.** Comparer le comportement aux
   descriptions des techniques de la/les tactique(s) retenue(s).
   - Plusieurs techniques peuvent s'appliquer **simultanément** au même
     comportement (ex. « C2 HTTP sur port 8088 » → Non-Standard Port `T1571`
     ET Application Layer Protocol: Web Protocols `T1071.001`).
   - **Ne pas supposer** une technique non explicitement étayée, sauf s'il
     n'existe aucune autre voie technique possible.
   - Vérifier que la technique s'aligne sur la bonne tactique (ex. Active
     Scanning `T1595` en Reconnaissance, AVANT compromission, ≠ Network Service
     Discovery `T1046` en Discovery, APRÈS compromission).
   Avec le serveur : confirmer **chaque** technique candidate via
   `get_technique(id)` et **lire sa description** avant de l'affirmer.

5. **Identifier la sous-technique.** Lire les descriptions des sous-techniques
   pour voir laquelle correspond. Si le rapport ne donne pas assez de détail,
   **mapper la technique parente seulement** (ex. Brute Force `T1110` sans
   préciser `.001`/`.002`/`.003`/`.004` faute de contexte).
   - Quand la technique parente couvre plusieurs tactiques, choisir la bonne
     (ex. Process Injection: DLL Injection `T1055.001` apparaît en Defense
     Evasion ET Privilege Escalation).

6. **Comparer / faire relire.** Le mapping gagne à être revu par un pair pour
   réduire les biais et révéler des techniques manquées. (Dans un usage
   assistant : exposer le raisonnement et les preuves pour que l'analyste
   humain valide ; signaler les passages incertains.)

## Deux modes d'entrée à traiter différemment

### Rapport fini (texte rédigé)
Plus de contexte, plus d'indices. Suivre les 6 étapes. Examiner aussi les
images, captures et exemples de ligne de commande : ils révèlent souvent des
techniques non citées explicitement dans le texte.

### Données brutes (logs, commandes, captures réseau, événements Windows)
Trois angles d'attaque possibles :
- **Par source de données.** Quel est l'objet visé (fichier, flux, processus,
  pilote) ? Quelle action ? Quelles techniques exigent cette activité ?
  Indices : outils connus (mimikatz, gsecdump — l'adversaire peut les renommer,
  mais les drapeaux de ligne de commande restent), composants système
  (regsvr32, rundll32), accès registre, scripts (.py/.js/.java), ports (22, 80),
  protocoles (RDP, DNS, SSH), obfuscation, type de machine (contrôleur de
  domaine…).
- **Par outil/attribut puis élargir.** Partir d'un outil ou d'un artefact
  observé (ex. clé de registre `...\CurrentVersion\Run` → Registry Run Keys
  `T1547.001`) et explorer les comportements associés.
- **Par analytique/règle de détection.** Partir d'une règle Sigma ou CAR ;
  beaucoup référencent déjà des techniques ATT&CK dans leurs tags.
  Avec le serveur : `get_datasources(query)` relie une source de détection aux
  techniques concernées.

## Profondeur : la règle d'or

Ne descendre au niveau sous-technique que si le détail le permet ; sinon
technique parente ; **tactique seule uniquement** s'il n'y a pas assez
d'information pour une technique — en sachant que la tactique seule n'est pas
actionnable pour la détection. Toujours mapper « à la profondeur la plus
précise que les preuves permettent », ni plus, ni moins.
